/**
 * @file Main module for the project.
 * @description This module exports the main functionality of the project.
 */

// ━━ MODULE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/**
 * The CryptoDriver class contain methods to encrypt and decrypt data.
 *
 * This class uses the AES-256-GCM encryption algorithm with a
 * 256-bit key, which is considered one of the most secure symmetric encryption
 * algorithms available.
 *
 * @version 2.0.2
 * @author Victor Giovanni Beltrán Rodríguez
 * @module CryptoDriver
 */
const CryptoDriver = require('./src');

// ━━ EXPORT MODULE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
module.exports = CryptoDriver;
