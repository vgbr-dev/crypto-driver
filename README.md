# CryptoDriver

The `CryptoDriver` is a simple and easy-to-use encryption class, manages cipher and decipher of data using the Advanced Encryption Standard (AES) `AES-256-GCM` algorithm with a user-provided key. This algorithm uses a 256-bit key and is considered one of the most secure symmetric encryption algorithms available.

## Table of Contents

- [Installation](##Installation)
- [Importing](##Importing)
- [Usage](##Usage)
- [API](##API)
  - [CryptoDriver(key)](###CryptoDriver(key))
  - [CryptoDriver#encrypt(data)](###CryptoDriver#encrypt(data))
  - [CryptoDriver#decrypt(encrypted)](###CryptoDriver#decrypt(encrypted))
- [Security Considerations](##Security-Considerations)
- [Contributing](##Contributing)
- [License](##License)

## Installation

You can install CryptoDriver via npm:

```sh
npm install crypto-driver
```

## Importing

To use CryptoDriver in your JavaScript application, first import it:

```js
// Using ES6 imports
import CryptoDriver from 'crypto-driver';

// Using Node.js `require()`
const CryptoDriver = require('crypto-driver');
```

## Usage

The `CryptoDriver` module is a class that needs to be instantiated with a key before it can be used. Once instantiated, you can use the `encrypt()` and `decrypt()` methods to encrypt and decrypt data.

```js
const CryptoDriver = require('crypto-driver');

const key = 'd6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq';
const crypto = new CryptoDriver(key);

const data = 'This is my secret message';

// Encrypt the original data
const encrypted = crypto.encrypt(data);

// Decrypt the encrypted data
const decrypted = crypto.decrypt(encrypted);

console.log(data); // This is my secret message
console.log(encrypted); // 2fV+Hd1vN6rByYjKsNixNl2eDvUJziG/6kKj8zJb+zk=BvLrZrTjTxbV6QAAAAA
console.log(decrypted ); // This is my secret message

```

## API

### `CryptoDriver(key)`

Creates an instance of the CryptoDriver class.

Arguments

| Name  | Type     | Description                                                                        |
|-------|----------|------------------------------------------------------------------------------------|
| `key` | `string` | The `key` used for encryption and decryption. Must be a `string` of 32 characters. |

Throws

| Type             | Description                                            |
|------------------|--------------------------------------------------------|
| `ReferenceError` | If the `key` value is `undefined`.                     |
| `TypeError`      | If the `key` value is not a `string`.                  |
| `RangeError`     | If the length of the `key` value is not 32 characters. |

Example

```js
const CryptoDriver = require('crypto-driver');

const key = 'd6F3Efeqd6F3Efeqd6F3Efeqd6F3Efeq';
const crypto = new CryptoDriver(key);
```

### `CryptoDriver#encrypt(data)`

Encrypts the specified data using the AES-256-GCM encryption algorithm.

Arguments

| Name   | Type     | Description                                   |
|--------|----------|-----------------------------------------------|
| `data` | `string` | The data to be encrypted. Must be a `string`. |

Returns

A `string` representing the encrypted data.

Throws

| Type             | Description                            |
|------------------|----------------------------------------|
| `ReferenceError` | If the `data` value is `undefined`.    |
| `TypeError`      | If the `data` value is not a `string`. |

Example

```js
const encrypted = crypto.encrypt('This is my secret message');
```

### `CryptoDriver#decrypt(encrypted)`

Decrypts the specified encrypted data using the AES-256-GCM encryption algorithm.

Arguments

| Name        | Type     | Description                                             |
|-------------|----------|---------------------------------------------------------|
| `encrypted` | `string` | The encrypted data to be decrypted. Must be a `string`. |

Returns

A `string` representing the decrypted data.

Throws

| Type             | Description                                 |
|------------------|---------------------------------------------|
| `ReferenceError` | If the `encrypted` value is `undefined`.    |
| `TypeError`      | If the `encrypted` value is not a `string`. |

Example

```js
const encrypted = crypto.encrypt('This is my secret message');
const decrypted = crypto.decrypt(encrypted);
```

## Security Considerations

When using CryptoDriver, it's important to keep in mind the following security considerations:

- Always use a strong encryption key. This means using a key that is long, random, and not easily guessable.
- Do not hardcode your encryption key in your application code. Instead, consider using an environment variable or other secure method for storing your key.
- Make sure to handle your encrypted data securely, especially when transmitting it over a network or storing it in a database. This may involve using additional security measures such as HTTPS or SSL/TLS.

## Contributing

If you encounter any bugs or issues with `CryptoDriver`, please open an issue on the GitHub repository. Pull requests are also welcome!

## License

CryptoDriver is released under the MIT License.
