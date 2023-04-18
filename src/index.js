/**
 * @author Victor Giovanni Beltrán Rodríguez
 * @file Manages `CryptoDriver` class related to cipher and decipher of data.
 */

// ━━ IMPORT MODULES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// » IMPORT NATIVE NODE MODULES
const crypto = require('crypto');

// ━━ TYPE DEFINITIONS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/**
 * Type definition for the cipher options object.
 *
 * @private
 * @typedef {crypto.CipherGCMOptions} CipherGCMOptions
 */

/**
 * Defines the structure of an object that holds error messages thrown by the
 * `CryptoDriver` class.
 *
 * @private
 * @typedef  {object} CryptoDriverErrors
 * @property {string} LENGTH_KEY          - Error message thrown when the `key` value is not 32 characters long.
 * @property {string} UNDEFINED_KEY       - Error message thrown when the `key` value is not provided.
 * @property {string} TYPE_KEY            - Error message thrown when the `key` value is not a string.
 * @property {string} UNDEFINED_DATA      - Error message thrown when the `data` value is not provided.
 * @property {string} TYPE_DATA           - Error message thrown when the `data` value is not a string.
 * @property {string} UNDEFINED_ENCRYPTED - Error message thrown when the `encrypted` value is not provided.
 * @property {string} TYPE_ENCRYPTED      - Error message thrown when the `encrypted` value is not a string.
 */

// ━━	CONSTANTS	━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/**
 * Algorithm used for encryption and decryption.
 *
 * @private
 * @constant ALGORITHM
 * @type {string}
 */
const ALGORITHM = 'aes-256-gcm';

/**
 * Length in bytes of the GCM auth tag used for encryption and decryption.
 *
 * @private
 * @constant TAG_BYTE_LENGTH
 * @type {number}
 */
const TAG_BYTE_LENGTH = 16;

/**
 * Length in bytes of the initialization vector (IV) used for encryption and
 * decryption.
 *
 * @private
 * @constant IV_BYTE_LENGTH
 * @type {number}
 */
const IV_BYTE_LENGTH = 12;

/**
 * Options object for the GCM auth tag length.
 *
 * @private
 * @constant IV_OPTIONS
 * @type {CipherGCMOptions}
 */
const IV_OPTIONS = {
  authTagLength: TAG_BYTE_LENGTH,
};

/**
 * Holds error messages thrown by the CryptoDriver class.
 *
 * @private
 * @constant ERRORS
 * @type {CryptoDriverErrors}
 */
const ERRORS = {
  LENGTH_KEY: 'The "Key" value must be 32 characters (256 bits).',
  UNDEFINED_KEY: 'The "key" value must be provided and must be a string.',
  TYPE_KEY: 'The "key" value must be of type string',
  UNDEFINED_DATA: 'The "data" value must be provided and must be a string.',
  TYPE_DATA: 'The "data" value must be of type string',
  UNDEFINED_ENCRYPTED: 'The "encrypted" value must be provided and must be a string.',
  TYPE_ENCRYPTED: 'The "encrypted" value must be of type string',
};

// ━━ MODULE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/**
 * The CryptoDriver class contain methods to encrypt and decrypt data.
 *
 * @class
 * @classdesc This class uses the AES-256-GCM encryption algorithm with a
 * 256-bit key, which is considered one of the most secure symmetric encryption
 * algorithms available.
 * @see {@link https://en.wikipedia.org/wiki/Advanced_Encryption_Standard Advanced Encryption Standard}
 * @see {@link https://en.wikipedia.org/wiki/Galois/Counter_Mode Galois/Counter Mode}
 *
 * @author Victor Giovanni Beltrán Rodríguez
 * @version 1.0.0
 */
class CryptoDriver {
  /**
   * Creates an instance of CryptoDriver, the `contructor` method require
   * the param `key` must be a string of 32 characters.
   *
   * @param {string} key - The key used for encryption and decryption.
   * @memberof CryptoDriver
   * @throws {ReferenceError} If `key` value is `undefined`.
   * @throws {TypeError} If `key` type is other than string.
   * @throws {RangeError} If `key` type length is other than 32.
   * @example
   * ```js
   * const crypto = new CryptoDriver('d6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq');
   *```
   */
  constructor(key) {
    if (key === undefined) throw new ReferenceError(ERRORS.UNDEFINED_KEY);
    if (typeof key !== 'string') throw new TypeError(ERRORS.TYPE_KEY);
    if (key.length !== 32) throw new RangeError(ERRORS.LENGTH_KEY);
    /**
     * Key used for encryption and decryption methods, must be of type string
     * with 32 characters.
     *
     * @name key
     * @memberof CryptoDriver#
     * @type {string}
     * @readonly
     */
    Object.defineProperty(this, 'key', {
      value: key,
      writable: false,
      enumerable: false,
      configurable: false,
    });
  }

  /**
   * Methods to encrypt data, encrypts a string using the AES-256-GCM
   * encryption algorithm with the key specified in the constructor.
   *
   * @param {string} data - Data to encrypt.
   * @returns {string} The encrypted data.
   * @memberof CryptoDriver
   * @throws {ReferenceError} If `data` value is `undefined`.
   * @throws {TypeError} If `data` type is other than string.
   * @example
   * ```js
   * const crypto = new CryptoDriver('d6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq');
   * const encrypted = crypto.encrypt('Hello world');
   * // Output like a e5be8c02e8d478b0ab9...8c28e6828010a5789a446e781f36d0
   *```
   */
  encrypt(data) {
    if (data === undefined) throw new ReferenceError(ERRORS.UNDEFINED_DATA);
    if (typeof data !== 'string') throw new TypeError(ERRORS.TYPE_DATA);
    const iv = crypto.randomBytes(IV_BYTE_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, this.key, iv, IV_OPTIONS);
    const raw = Buffer.from(data, 'utf-8');
    const encrypted = Buffer.concat([iv, cipher.update(raw), cipher.final(), cipher.getAuthTag()]);
    return encrypted.toString('hex');
  }

  /**
   * Methods to decrypt data.
   *
   * @param {string} encrypted - Encrypted data.
   * @returns {string} Decrypted data.
   * @memberof CryptoDriver
   * @throws {ReferenceError} If `encrypted` value is `undefined`.
   * @throws {TypeError} If `encrypted` type is other than string.
   * @example
   * ```js
   * // Output like a e5be8c02e8d478b0ab9...8c28e6828010a5789a446e781f36d0
   * const encrypted = cryptoDriver.encrypt('Hello world');
   * const decrypted = cryptoDriver.decrypt(encrypted); // Hello world
   *```
   */
  decrypt(encrypted) {
    if (encrypted === undefined) throw new ReferenceError(ERRORS.UNDEFINED_ENCRYPTED);
    if (typeof encrypted !== 'string') throw new TypeError(ERRORS.TYPE_ENCRYPTED);
    const cipher = Buffer.from(encrypted, 'hex');
    const iv = cipher.subarray(0, IV_BYTE_LENGTH);
    const data = cipher.subarray(IV_BYTE_LENGTH, cipher.length - TAG_BYTE_LENGTH);
    const authTag = cipher.subarray(data.length + IV_BYTE_LENGTH);
    const decipher = crypto.createDecipheriv(ALGORITHM, this.key, iv, IV_OPTIONS);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
    return decrypted.toString('utf-8');
  }
}

// ━━	EXPORT MODULES	━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
module.exports = CryptoDriver;
