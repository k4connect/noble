var debug = require('debug')('smp');

var events = require('events');
var util = require('util');

var crypto = require('./crypto');

var SMP_CID = 0x0006;

var SMP_PAIRING_REQUEST = 0x01;
var SMP_PAIRING_RESPONSE = 0x02;
var SMP_PAIRING_CONFIRM = 0x03;
var SMP_PAIRING_RANDOM = 0x04;
var SMP_PAIRING_FAILED = 0x05;
var SMP_ENCRYPT_INFO = 0x06;
var SMP_MASTER_IDENT = 0x07;
var SMP_SECURITY_REQUEST = 0x0b;

var Smp = function(aclStream, localAddressType, localAddress, remoteAddressType, remoteAddress, passkeyProvider) {
  this._aclStream = aclStream;

  this._iat = new Buffer([(localAddressType === 'random') ? 0x01 : 0x00]);
  this._ia = new Buffer(localAddress.split(':').reverse().join(''), 'hex');
  this._rat = new Buffer([(remoteAddressType === 'random') ? 0x01 : 0x00]);
  this._ra = new Buffer(remoteAddress.split(':').reverse().join(''), 'hex');

  this.onAclStreamDataBinded = this.onAclStreamData.bind(this);
  this.onAclStreamEndBinded = this.onAclStreamEnd.bind(this);

  this._aclStream.on('data', this.onAclStreamDataBinded);
  this._aclStream.on('end', this.onAclStreamEndBinded);

  this._remoteAddress = remoteAddress;

  if(passkeyProvider)
    this._passkeyProvider = passkeyProvider;
  else
    this._passkeyProvider = Promise.resolve;
};

util.inherits(Smp, events.EventEmitter);

Smp.prototype.sendPairingRequest = function() {
  this._preq = new Buffer([
    SMP_PAIRING_REQUEST,
    0x04, // IO capability: KeyboardDisplay
    0x00, // OOB data: Authentication data not present
    0x01, // Authentication requirement: Bonding - No MITM
    0x10, // Max encryption key size
    0x00, // Initiator key distribution: <none>
    0x01  // Responder key distribution: EncKey
  ]);

  this.write(this._preq);
};

Smp.prototype.onAclStreamData = function(cid, data) {
  if (cid !== SMP_CID) {
    return;
  }

  var code = data.readUInt8(0);

  if (SMP_PAIRING_RESPONSE === code) {
    this.handlePairingResponse(data);
  } else if (SMP_PAIRING_CONFIRM === code) {
    this.handlePairingConfirm(data);
  } else if (SMP_PAIRING_RANDOM === code) {
    this.handlePairingRandom(data);
  } else if (SMP_PAIRING_FAILED === code) {
    this.handlePairingFailed(data);
  } else if (SMP_ENCRYPT_INFO === code) {
    this.handleEncryptInfo(data);
  } else if (SMP_MASTER_IDENT === code) {
    this.handleMasterIdent(data);
  } else if (SMP_SECURITY_REQUEST === code) {
    this.handleSecurityRequest(data);
  }
};

Smp.prototype.onAclStreamEnd = function() {
  this._aclStream.removeListener('data', this.onAclStreamDataBinded);
  this._aclStream.removeListener('end', this.onAclStreamEndBinded);

  this.emit('end');
};

Smp.prototype.handlePairingResponse = function(data) {
  this._pres = data;

  this._tk = new Buffer('00000000000000000000000000000000', 'hex');
  this._passkeyProvider(this._remoteAddress.toLowerCase().replace(/\:/g, ''))
  .then(passkey => {
    if(passkey)
      this._tk.writeUInt32LE(passkey, 0);
    this._r = crypto.r();

    this.write(Buffer.concat([
      new Buffer([SMP_PAIRING_CONFIRM]),
      crypto.c1(this._tk, this._r, this._pres, this._preq, this._iat, this._ia, this._rat, this._ra)
    ]));
  })
  .catch(e => console.error("Error handling SMP pairing response:", e));
};

Smp.prototype.handlePairingConfirm = function(data) {
  this._pcnf = data;

  this.write(Buffer.concat([
    new Buffer([SMP_PAIRING_RANDOM]),
    this._r
  ]));
};

Smp.prototype.handlePairingRandom = function(data) {
  var r = data.slice(1);

  var pcnf = Buffer.concat([
    new Buffer([SMP_PAIRING_CONFIRM]),
    crypto.c1(this._tk, r, this._pres, this._preq, this._iat, this._ia, this._rat, this._ra)
  ]);

  if (this._pcnf.toString('hex') === pcnf.toString('hex')) {
    var stk = crypto.s1(this._tk, r, this._r);

    this.emit('stk', stk);
  } else {
    this.write(new Buffer([
      SMP_PAIRING_RANDOM,
      SMP_PAIRING_CONFIRM
    ]));

    this.emit('fail');
  }
};

Smp.prototype.handlePairingFailed = function(data) {
  this.emit('fail');
};

Smp.prototype.handleEncryptInfo = function(data) {
  var ltk = data.slice(1);

  this.emit('ltk', ltk);
};

Smp.prototype.handleMasterIdent = function(data) {
  var ediv = data.slice(1, 3);
  var rand = data.slice(3);

  this.emit('masterIdent', ediv, rand);
};

Smp.prototype.handleSecurityRequest = function(data) {
  this.sendPairingRequest();
}

Smp.prototype.write = function(data) {
  // Disable SMP writing, as it interferes with bluez.
  // Kyle Strickland <kyle@k4connect.com> 2018-04-30
  //this._aclStream.write(SMP_CID, data);
};

module.exports = Smp;
