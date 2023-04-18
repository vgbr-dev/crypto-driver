/**
 * @author Victor Giovanni Beltrán Rodríguez
 * @file This file contains the test for the `CryptoDriver` class.
 */

// ━━ IMPORT MODULES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// » IMPORT NATIVE NODE MODULES
const { describe, it } = require('node:test');
const assert = require('node:assert');

// » IMPORT MODULES
const CryptoDriver = require('..');

// ━━ CONSTANTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/**
 * This constant defines the errors that can be thrown by
 * the `CryptoDriver` class.
 *
 * @private
 * @constant {object} THROWS
 */
const THROWS = {
  UNDEFINED_PASSWORD: {
    name: 'ReferenceError',
    message: 'The "password" value must be provided and must be a string.',
  },
  TYPE_PASSWORD: {
    name: 'TypeError',
    message: 'The "password" value must be of type string',
  },
  UNDEFINED_DATA: {
    name: 'ReferenceError',
    message: 'The "data" value must be provided and must be a string.',
  },
  TYPE_DATA: {
    name: 'TypeError',
    message: 'The "data" value must be of type string',
  },
  UNDEFINED_ENCRYPTED: {
    name: 'ReferenceError',
    message: 'The "encrypted" value must be provided and must be a string.',
  },
  TYPE_ENCRYPTED: {
    name: 'TypeError',
    message: 'The "encrypted" value must be of type string',
  },
};

// ━━ CONSTANTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/**
 * Add description.
 *
 * @private
 * @function createInstance
 * @param {string} key  - Add description.
 * @returns {CryptoDriver} Add description.
 * @example createInstance(d6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq);
 *
 */
const createInstance = key => new CryptoDriver(key);

// ━━ TEST ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
describe('CryptoDriver', () => {
  describe('constructor', () => {
    it('should create a new instance of CryptoDriver with a valid key', () => {
      const cryptoDriver = new CryptoDriver('this is secret');
      assert.ok(cryptoDriver instanceof CryptoDriver);
    });

    it('should throw a ReferenceError if key is undefined', () => {
      assert.throws(() => {
        createInstance(undefined);
      }, THROWS.UNDEFINED_PASSWORD);
    });

    it('should throw a TypeError if key is not a string', () => {
      assert.throws(() => {
        createInstance(true);
      }, THROWS.TYPE_PASSWORD);
      assert.throws(() => {
        createInstance(100);
      }, THROWS.TYPE_PASSWORD);
    });
  });

  describe('#encrypt()', () => {
    it('should encrypt data and return the encrypted value', () => {
      const cryptoDriver = new CryptoDriver('d6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq');
      const encryptedData = cryptoDriver.encrypt('hello world');
      assert.notStrictEqual(encryptedData, 'hello world');
    });

    it('should throw a ReferenceError if data is undefined', () => {
      assert.throws(() => {
        const cryptoDriver = new CryptoDriver('d6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq');
        cryptoDriver.encrypt();
      }, THROWS.UNDEFINED_DATA);
    });

    it('should throw a TypeError if data is not a string', () => {
      assert.throws(() => {
        const cryptoDriver = new CryptoDriver('d6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq');
        cryptoDriver.encrypt(true);
      }, THROWS.TYPE_DATA);
      assert.throws(() => {
        const cryptoDriver = new CryptoDriver('d6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq');
        cryptoDriver.encrypt(100);
      }, THROWS.TYPE_DATA);
    });
  });

  describe('#decrypt()', () => {
    it('should decrypt data and return the original value', () => {
      const cryptoDriver = new CryptoDriver('d6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq');
      const encryptedData = cryptoDriver.encrypt('hello world');
      const decryptedData = cryptoDriver.decrypt(encryptedData);
      assert.strictEqual(decryptedData, 'hello world');
    });

    it('should throw a ReferenceError if encrypted is undefined', () => {
      assert.throws(() => {
        const cryptoDriver = new CryptoDriver('d6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq');
        cryptoDriver.decrypt();
      }, THROWS.UNDEFINED_ENCRYPTED);
    });

    it('should throw a TypeError if encrypted is not a string', () => {
      assert.throws(() => {
        const cryptoDriver = new CryptoDriver('d6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq');
        cryptoDriver.decrypt(true);
      }, THROWS.TYPE_ENCRYPTED);
      assert.throws(() => {
        const cryptoDriver = new CryptoDriver('d6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq');
        cryptoDriver.decrypt(100);
      }, THROWS.TYPE_ENCRYPTED);
    });
  });
});
