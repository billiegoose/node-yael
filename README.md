# Yael [![Build Status](https://travis-ci.org/wmhilton/node-yael.svg)](https://travis-ci.org/wmhilton/node-yael) ![Node Version](https://img.shields.io/badge/node-%3Ev0.11.10-lightgrey.svg)
[![NPM](https://nodei.co/npm/yael.png)](https://nodei.co/npm/yael/)

Yael === Yet Another Encryption Library

But seriously, this one is better. Just trust me. Why would I contribute another encryption library to the multiverse if I didn't think it had something wonderful to offer? With that in mind...

## ... The Yael Philosophy
An encryption/decryption library should:
* Be **simple** to use.
* Have **secure** default settings.
* Support common Node.js interface paradigms like:
  * [Callbacks](http://thenodeway.io/posts/understanding-error-first-callbacks/)
  * [Streams](https://nodejs.org/api/stream.html) (planned)
  * [Promises](https://www.npmjs.com/package/bluebird) (planned)
* Have as few dependencies as possible.
* Have well-documented source code that you can read and audit yourself.

An encryption/decryption library should NOT:
* Require the user to understand key derivation functions, hash functions, block ciphers, initialization vectors, and authentication schemes.
* Have lots of settings like key-length and iv-length but only work with certain undocumented combinations of settings.
* Have insecure default settings or use deprecated algorithms in order to be compatible with older software.

The former describes this library, the latter describes the native 'crypto' library in Node.js. (!!!)

## API
### yael.encrypt( *passphrase*, *plainfile*, *callback* )
Arguments:
* `passphrase`: String. A secret password used to encrypt the plainfile.
* `plainfile`: String or Buffer. Either a string or buffer whose contents will be encrypted using the passphrase.
* `callback`: Function( Error, CipherObject ). Error-first callback that gets called with the encrypted result.

Returns: `null`

### yael.decrypt( *passphrase*, *cipherObject*, *callback* )
Arguments:
* `passphrase`: String. A secret password used to encrypt the plainfile.
* `cipherObject`: CipherObject. The encrypted content.
* `callback`: Function( Error, String|Buffer ). Error-first callback that gets called with the decrypted result.

Returns: `null`

## yael.CipherObject

### CipherObject.toString()
Serializes the cipher object to a string. JSON format, but with buffers encoded using base64 like the json-buffer package.

### CipherObject.toBuffer()
Serializes the cipher object to a buffer. An unreadable binary blob of a format.

### new CipherObject (String | Buffer)
Deserializes a cipher object thats been serialized.

### Properties:

- `yael_version`: String (semver version from package.json)
- `cipherfile`: Buffer
- `iv`: Buffer
- `salt`: Buffer
- `authtag`: Buffer
- `return_type`: String ('String' | 'Buffer')
- `details`:
  - `CIPHER_ALGORITHM`: String
  - `SALT_LENGTH`: Number
  - `IV_LENGTH`: Number
  - `KEY_LENGTH`: Number
  - `HASH_ALGORITHM`: String
  - `ITERATIONS`: Number
