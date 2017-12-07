/**
ethereumjs-accounts - A suite for managing Ethereum accounts in browser.

Welcome to ethereumjs-accounts. Generate, encrypt, manage, export and remove Ethereum accounts and store them in your browsers local storage. You may also choose to extendWeb3 so that transactions made from accounts stored in browser, can be signed with the private key provided. EthereumJs-Accounts also supports account encryption using the AES encryption protocol. You may choose to optionally encrypt your Ethereum account data with a passphrase to prevent others from using or accessing your account.

Requires:
- cryptojs v0.3.1  <https://github.com/fahad19/crypto-js>
- localstorejs *  <https://github.com/SilentCicero/localstore>
- ethereumjs-tx v0.4.0  <https://www.npmjs.com/package/ethereumjs-tx>
- ethereumjs-tx v1.2.0  <https://www.npmjs.com/package/ethereumjs-util>
- Underscore.js v1.8.3+  <http://underscorejs.org/>
- Web3.js v0.4.2+ <https://github.com/ethereum/web3.js>

Commands:
(Browserify)
browserify --s Accounts index.js -o dist/ethereumjs-accounts.js

(Run)
node index.js

(NPM)
npm install ethereumjs-accounts

(Meteor)
meteor install silentcicero:ethereumjs-accounts
**/

var _ = require('underscore');
var Tx = require('ethereumjs-tx');
var BigNumber = require('bignumber.js');
var JSZip = require("jszip");
var FileSaver = require("node-safe-filesaver");
var crypto = require('crypto');
global.CryptoJS = require('browserify-cryptojs');
require('browserify-cryptojs/components/enc-base64');
require('browserify-cryptojs/components/md5');
require('browserify-cryptojs/components/evpkdf');
require('browserify-cryptojs/components/cipher-core');
require('browserify-cryptojs/components/aes');

/**
The Accounts constructor method. This method will construct the in browser Ethereum accounts manager.

@class Accounts
@constructor
@method (Accounts)
@param {Object} options       The accounts object options.
**/

var Accounts = module.exports = function(options){
  if(_.isUndefined(options))
  options = {};

  // setup default options
  var defaultOptions = {
    varName: 'ethereumAccounts'
    , minPassphraseLength: 6
    , requirePassphrase: false
    , selectNew: true
    , defaultGasPrice: 'useWeb3'
    , request: function(accountObject){
      var passphrase = prompt("Please enter your account passphrase for address " + accountObject.address.substr(0, 8) + '...', "passphrase");

      if(passphrase == null)
      passphrase = '';

      return String(passphrase);
    }
  };

  // build options
  this.options = _.extend(defaultOptions, options);

  // define Accounts object properties
  defineProperties(this);
};


/**
Pad the given string with a prefix zero, if length is uneven.

@method (formatHex)
@param {String} str    The string to pad for use as hex
@return {String} The padded or formatted string for use as a hex string
**/

var formatHex = function(str){
  if(_.isUndefined(str))
  str = '00';

  return String(str).length % 2 ? '0' + String(str) : String(str);
};


/**
Prepair numbers for raw transactions.

@method (formatNumber)
@param {Number|String|BigNumber} The object to be used as a number
@return {String} The padded, toString hex value of the number
**/

var formatNumber = function(num){
  if(_.isUndefined(num) || num == 0)
  num = '00';

  if(_.isString(num) || _.isNumber(num))
  num = new BigNumber(String(num));

  if(isBigNumber(num))
  num = num.toString(16);

  return formatHex(num);
};


/**
Prepair Ethereum address for either raw transactions or browser storage.

@method (formatAddress)
@param {String} addr    An ethereum address to prep
@param {String} format          The format type (i.e. 'raw' or 'hex')
@return {String} The prepaired ethereum address
**/

var formatAddress = function(addr, format){
  if(_.isUndefined(format) || !_.isString(format))
  format = 'hex';

  if(_.isUndefined(addr)
  || !_.isString(addr))
  addr = '0000000000000000000000000000000000000000';

  if(addr.substr(0, 2) == '0x' && format == 'raw')
  addr = addr.substr(2);

  if(addr.substr(0, 2) != '0x' && format == 'hex')
  addr = '0x' + addr;

  return addr;
};


/**
Generate 16 random alpha numeric bytes.

@method (randomBytes)
@param {Number} length      The string length that should be generated
@return {String} A 16 char/UTF-8 byte string of random alpha-numeric characters
**/

var randomBytes = function(length) {
  var charset = "abcdef0123456789";
  var i;
  var result = "";
  var values = crypto.randomBytes(length);
  for(i=0; i<length; i++) {
    result += charset[values[i] % charset.length];
  }

  return result;
}


/**
Is the object provided a Bignumber object.

@method (isBigNumber)
**/

var isBigNumber = function(value){
  if(_.isUndefined(value) || !_.isObject(value))
  return false;

  return (value instanceof BigNumber) ? true : false;
};

/**
* Checks if the given string is an address
*
* @method isAddress
* @param {String} address the given HEX adress
* @return {Boolean}
**/

var isAddress = function (address) {
  return /^(0x)?[0-9a-f]{40}$/.test(address);
};


/**
Define object properties such as 'length'.

@method (defineProperties)
@param {Object} context     The Accounts object context
**/

var defineProperties = function(context){
  Object.defineProperty(context, 'length', {
    get: function() {
      var count = 0;

      // count valid accounts in browser storage
      _.each(this.get(), function(account, accountIndex){
        if(_.isUndefined(account)
        || !_.isObject(account)
        || _.isString(account))
        return;

        if(!_.has(account, 'encrypted')
        || !_.has(account, 'private'))
        return;

        count += 1;
      });

      return count;
    }
  });
};


/**
Returns true when a valid passphrase is provided.

@method (isPassphrase)
@param {String} passphrase    A valid ethereum passphrase
@return {Boolean} Whether the passphrase is valid or invalid.
**/

Accounts.prototype.isPassphrase = function(passphrase){
  if(!_.isUndefined(passphrase)
  && _.isString(passphrase)
  && !_.isEmpty(passphrase)
  && String(passphrase).length > this.options.minPassphraseLength)
  return true;
};

/**
Generate a new Ethereum account in browser with a passphrase that will encrypt the public and private keys with AES for storage.

@method (new)
@param {String} passphrase          The passphrase to encrypt the public and private keys.
@return {Object} an account object with the public and private keys included.
**/

Accounts.prototype.new = function(passphrase){
  var private = new Buffer(randomBytes(64), 'hex');
  var public = ethUtil.privateToPublic(private);
  var address = formatAddress(ethUtil.publicToAddress(public).toString('hex'));
  var accountObject = {
    address: address
    , encrypted: false
    , locked: false
    , hash: ethUtil.sha3(public.toString('hex') + private.toString('hex')).toString('hex')
  };

  // if passphrrase provided or required, attempt account encryption
  if((!_.isUndefined(passphrase) && !_.isEmpty(passphrase))
  || this.options.requirePassphrase){
    if(this.isPassphrase(passphrase)) {
      private = CryptoJS.AES
      .encrypt(private.toString('hex'), passphrase)
      .toString();
      public = CryptoJS.AES
      .encrypt(public.toString('hex'), passphrase)
      .toString();
      accountObject.encrypted = true;
      accountObject.locked = true;
    } else {
      this.log('The passphrase you tried to use was invalid.');
      private = private.toString('hex')
      public = public.toString('hex')
    }
  } else {
    private = private.toString('hex')
    public = public.toString('hex')
  }

  // Set account object private and public keys
  accountObject.private = private;
  accountObject.public = public;

  this.log('New address created');

  return accountObject;
};


/**
Get an account object that is stored in local browser storage. If encrypted, decrypt it with the passphrase.

@method (new)
@param {String} passphrase          The passphrase to encrypt the public and private keys.
@return {Object} an account object with the public and private keys included.
**/

Accounts.prototype.decrypt = function(account, passphrase){
  var accountObject = this.clone(account);

  if(_.isEmpty(accountObject)) {
    return accountObject;
  }

  // If a passphrase is provided, decrypt private and public key
  if(this.isPassphrase(passphrase) && accountObject.encrypted) {
    try {
      accountObject.private = CryptoJS.AES
      .decrypt(accountObject.private, passphrase)
      .toString(CryptoJS.enc.Utf8);
      accountObject.public = CryptoJS.AES
      .decrypt(accountObject.public, passphrase)
      .toString(CryptoJS.enc.Utf8);

      if(ethUtil.sha3(accountObject.public + accountObject.private).toString('hex') == accountObject.hash)
      accountObject.locked = false;
    }catch(e){
      this.log('Error while decrypting public/private keys: ' + String(e));
      return undefined;
    }
  }

  return accountObject;
};

Accounts.prototype.clone = function(account) {
  return {
    address: account.address,
    encrypted: account.encrypted,
    locked: account.locked,
    hash: account.hash,
    public: account.public,
    private: account.private
  }
}


/**
Import a JSON ready string. This will import JSON data, parse it, and attempt to use it as accounts data.

@method (import)
@param {String} A JSON ready string
@return {String} How many accountObject's were added
**/

Accounts.prototype.import = function(JSON_data){
  var JSON_data = JSON_data.trim();
  var parsed = JSON.parse(JSON_data);
  var count = 0;
  var _this = this;
  var accounts = [];

  _.each(parsed, function(accountObject, accountIndex){
    if(!_.has(accountObject, 'private')
    || !_.has(accountObject, 'hash')
    || !_.has(accountObject, 'address')
    || !_.has(accountObject, 'encrypted')
    || !_.has(accountObject, 'locked'))
    return;

    count += 1;
    accounts.push(accountObject);
  });

  this.log('Imported ' + String(count) + ' accounts');

  return accounts;
};

/**
A log function that will log all actions that occur with ethereumjs-accounts.

@method (log)
**/

Accounts.prototype.log = function(){};

/**
This will sign a transaction based on transaction parameters passed to it.
If the from address is not registered as an in-browser account, signTransaction
will respond with an error.

This method is required to be a part of the transaction_signer specification for
the HookedWeb3Provider.

tx_params should be an object passed directly from web3. All data should be hex
and start with the prefix "0x". nonce is required.

@method (signTransaction)
**/
Accounts.prototype.signTransaction = function(tx_params, account, callback) {

  if(!account.encrypted) {
    callback(new Error("The account must be encrypted for security reason"));
    return;
  }

  // if account is still locked, quit
  if(account.locked) {
    callback(new Error("Cannot sign transaction. Account locked!"));
    return;
  }

  var rawTx = {
    nonce: formatHex(ethUtil.stripHexPrefix(tx_params.nonce)),
    gasPrice: formatHex(ethUtil.stripHexPrefix(tx_params.gasPrice)),
    gasLimit: formatHex(new BigNumber('3141592').toString(16)),
    value: '00',
    data: ''
  };

  if(tx_params.gasPrice != null)
  rawTx.gasPrice = formatHex(ethUtil.stripHexPrefix(tx_params.gasPrice));

  if(tx_params.gas != null)
  rawTx.gasLimit = formatHex(ethUtil.stripHexPrefix(tx_params.gas));

  if(tx_params.to != null)
  rawTx.to = formatHex(ethUtil.stripHexPrefix(tx_params.to));

  if(tx_params.value != null)
  rawTx.value = formatHex(ethUtil.stripHexPrefix(tx_params.value));

  if(tx_params.data != null)
  rawTx.data = formatHex(ethUtil.stripHexPrefix(tx_params.data));

  // convert string private key to a Buffer Object
  var privateKey = new Buffer(account.private, 'hex');

  function signTx(err){
    // init new transaction object, and sign the transaction
    var tx = new Tx(rawTx);
    tx.sign(privateKey);

    // Build a serialized hex version of the Tx
    var serializedTx = '0x' + tx.serialize().toString('hex');

    // fire callback
    callback(err, serializedTx);
  };
  signTx(null);
};
