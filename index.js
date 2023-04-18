/**
 * @author Victor Giovanni Beltrán Rodríguez
 * @file Manages main entry point.
 */

// ━━ TYPE DEFINITIONS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/**
 * The CryptoDriver class contain methods to encrypt and decrypt data.
 *
 * This class uses the AES-256-GCM encryption algorithm with a
 * 256-bit key, which is considered one of the most secure symmetric encryption
 * algorithms available.
 *
 * @version 1.0.0
 * @author Victor Giovanni Beltrán Rodríguez
 * @module CryptoDriver
 */
const CryptoDriver = require('./src');

// ━━ EXPORT MODULE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
module.exports = CryptoDriver;
