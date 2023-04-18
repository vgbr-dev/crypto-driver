# CryptoDriver

CryptoDriver is a simple and easy-to-use encryption library for JavaScript applications. It provides a way to encrypt and decrypt data using the Advanced Encryption Standard (AES) algorithm with a user-provided key 🔑.

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

## Overview

### Create instance

Then, create a new instance of the CryptoDriver class with your encryption key:

```js
const key = 'e79b44ab0dbb6934385921e95aaaf67fa88e61c0a0ca44f841da3729604ef62a145be70de13ed1';
const cryptoDriver = new CryptoDriver(key);
```

### Use methods

You can then use the encrypt and decrypt methods to encrypt and decrypt data, respectively:

```js
const plaintext = 'Hello, world!';
const ciphertext = cryptoDriver.encrypt(plaintext);
const decryptedText = cryptoDriver.decrypt(ciphertext);
console.log(decryptedText); // Output: Hello, world!

```

See [documentation](https://github.com/vgbr-dev/crypto-driver/wiki#cryptodriver) for more details.

## Security Considerations

When using CryptoDriver, it's important to keep in mind the following security considerations:

- Always use a strong encryption key. This means using a key that is long, random, and not easily guessable.
- Do not hardcode your encryption key in your application code. Instead, consider using an environment variable or other secure method for storing your key.
- Make sure to handle your encrypted data securely, especially when transmitting it over a network or storing it in a database. This may involve using additional security measures such as HTTPS or SSL/TLS.

## Contributing

If you encounter any bugs or issues with `CryptoDriver`, please open an issue on the GitHub repository. Pull requests are also welcome!

## License

CryptoDriver is released under the MIT License.
