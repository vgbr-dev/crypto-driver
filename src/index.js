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
 * Options object for the Scrypt function used to generate the key.
 *
 * @private
 * @typedef {crypto.ScryptOptions} ScryptOptions
 */

/**
 * Defines the structure of an object that holds error messages thrown by the
 * `CryptoDriver` class.
 *
 * @typedef  {object} CryptoDriverErrors
 * @property {string} UNDEFINED_PASSWORD  - Error message thrown when the `password` value is not provided.
 * @property {string} TYPE_PASSWORD       - Error message thrown when the `password` value is not a string.
 * @property {string} UNDEFINED_DATA      - Error message thrown when the `data` value is not provided.
 * @property {string} TYPE_DATA           - Error message thrown when the `data` value is not a string.
 * @property {string} UNDEFINED_ENCRYPTED - Error message thrown when the `encrypted` value is not provided.
 * @property {string} TYPE_ENCRYPTED      - Error message thrown when the `encrypted` value is not a string.
 */

// ━━	CONSTANTS	━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
 * Length in bytes of the key used for encryption and decryption.
 *
 * @private
 * @constant KEY_BYTE_LENGTH
 * @type {number}
 */
const KEY_BYTE_LENGTH = 32;

/**
 * Length in bytes of the salt used for encryption and decryption.
 *
 * @private
 * @constant SALT_BYTE_LENGTH
 * @type {number}
 */
const SALT_BYTE_LENGTH = 16;

/**
 * Options object for the GCM auth tag length.
 *
 * @private
 * @constant IV_OPTIONS
 * @type {CipherGCMOptions} IV_OPTIONS
 */
const IV_OPTIONS = {
  authTagLength: TAG_BYTE_LENGTH,
};

/**
 * Options object for the Scrypt function used to generate the key.
 *
 * @private
 * @constant CREATE_KEY_OPTIONS
 * @type {ScryptOptions}
 */
const CREATE_KEY_OPTIONS = {
  cost: 16384,
  blockSize: 8,
  parallelization: 1,
};

/**
 * Add description.
 *
 * @private
 * @constant ERRORS
 * @type {CryptoDriverErrors}
 */
const ERRORS = {
  UNDEFINED_PASSWORD: 'The "password" value must be provided and must be a string.',
  TYPE_PASSWORD: 'The "password" value must be of type string',
  UNDEFINED_DATA: 'The "data" value must be provided and must be a string.',
  TYPE_DATA: 'The "data" value must be of type string',
  UNDEFINED_ENCRYPTED: 'The "encrypted" value must be provided and must be a string.',
  TYPE_ENCRYPTED: 'The "encrypted" value must be of type string',
};

// ━━	FUNCTIONS	━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/**
 * Generates a cryptographically strong pseudo-random data for Initialization
 * Vector (IV). Returns a `Buffer` based on `12 bytes` size.
 *
 * @private
 * @function createIV
 * @returns {Buffer} A Buffer containing the generated random bytes for the IV.
 * @example createIV(); // <Buffer 4b d4 62 fd b1 6c d8 d5 52 66 d5 d1>
 *
 */
const createIV = () => crypto.randomBytes(IV_BYTE_LENGTH);

/**
 * Generates a cryptographically strong pseudo-random data for salt. Returns a
 * `Buffer` based on `16 bytes` size.
 *
 * @private
 * @function createSalt
 * @returns {Buffer}  A Buffer containing the generated random bytes for the salt.
 * @example createSalt(); // <Buffer 44 7c c3 f8 a5 12 ad 79 f3 98 1e 1b 06 cc be 31>
 *
 */
const createSalt = () => crypto.randomBytes(SALT_BYTE_LENGTH);

/**
 * Generates a derived key from a given password and salt using a password-based
 * key derivation function (PBKDF). Returns a `Buffer` based on `32 bytes` size.
 *
 * @private
 * @function createKey
 * @param {string} password - The password to use for key derivation.
 * @param {string} salt - The salt value to use for key derivation.
 * @returns {Buffer}  A Buffer containing the derived key.
 * @example createKey('This is secret', salt); // <Buffer 95 9a 89 50 c6 ff 9d 74 5e 42 72 7d e1 1c 1c 50 14 e6 fe 57 b0 63 fc 28 2d a5 9f b5 ec 41 72 b4>
 *
 */
const createKey = (password, salt) => crypto.scryptSync(password, salt, KEY_BYTE_LENGTH, CREATE_KEY_OPTIONS); // eslint-disable-line prettier/prettier

// ━━	MODULE	━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
 * @version 2.0.0
 */
class CryptoDriver {
  /**
   * Creates an instance of CryptoDriver, the `contructor` method require
   * the param `password` must be a string.
   *
   * @param {string} password - The password used for encryption and decryption.
   * @memberof CryptoDriver
   * @throws {ReferenceError} If `password` value is `undefined`.
   * @throws {TypeError} If `password` type is other than string.
   * @example
   * ```js
   * const crypto = new CryptoDriver('This is a secret');
   *```
   */
  constructor(password) {
    if (password === undefined) throw new ReferenceError(ERRORS.UNDEFINED_PASSWORD);
    if (typeof password !== 'string') throw new TypeError(ERRORS.TYPE_PASSWORD);
    /**
     * The `password` used for encryption and decryption methods, must be of type string
     * with 32 characters.
     *
     * @name password
     * @memberof CryptoDriver#
     * @type {string}
     * @readonly
     */
    Object.defineProperty(this, 'password', {
      value: password,
      writable: false,
      enumerable: false,
      configurable: false,
    });
  }

  /**
   * Methods to encrypt data, encrypts a string using the AES-256-GCM
   * encryption algorithm with the `password` specified in the constructor.
   *
   * @param {string} data - Data to encrypt.
   * @returns {string} Encrypted data.
   * @memberof CryptoDriver
   * @throws {ReferenceError} If `data` value is `undefined`.
   * @throws {TypeError} If `data` type is other than string.
   * @example
   * ```js
   * const crypto = new CryptoDriver('This is a secret');
   * const encrypted = crypto.encrypt('Hello world');
   * // Output like a e5be8c02e8d478b0ab9...8c28e6828010a5789a446e781f36d0
   *```
   */
  encrypt(data) {
    const iv = createIV();
    const salt = createSalt();
    const key = createKey(this.password, salt);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, IV_OPTIONS);
    const raw = Buffer.from(data, 'utf-8');
    const encrypted = Buffer.concat([salt, iv, cipher.update(raw), cipher.final(), cipher.getAuthTag()]); // eslint-disable-line prettier/prettier
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
    const cipher = Buffer.from(encrypted, 'hex');
    const salt = cipher.subarray(0, SALT_BYTE_LENGTH);
    const iv = cipher.subarray(SALT_BYTE_LENGTH, SALT_BYTE_LENGTH + IV_BYTE_LENGTH);
    const input = cipher.subarray(IV_BYTE_LENGTH + SALT_BYTE_LENGTH, cipher.length - TAG_BYTE_LENGTH); // eslint-disable-line prettier/prettier
    const authTag = cipher.subarray(input.length + IV_BYTE_LENGTH + SALT_BYTE_LENGTH);
    const key = createKey(this.password, salt);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, IV_OPTIONS);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(input);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    decrypted = decrypted.toString('utf-8');
    return decrypted;
  }
}

// ━━	EXPORT MODULES	━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
module.exports = CryptoDriver;
