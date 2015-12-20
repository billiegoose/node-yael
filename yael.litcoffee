# Yet Another Encryption Library

    crypto = require 'crypto'
    semver = require 'semver'
    pkg = require './package.json'
    CipherObject = require './CipherObject'
    E = require './constants'

I'm trying to keep dependencies to a minimum. Semver is used to do backwards-compatibility checks though.

    encrypt = (passphrase, plainfile, callback) ->
      return switch arguments.length
        # Return Writable Stream
        when 1 then encryptStream(passphrase)
        # Return Promise
        when 2 then encryptPromise(passphrase, plainfile)
        # Encrypt then call callback
        when 3 then encryptAsync(passphrase, plainfile, callback)
    decrypt = (passphrase, cipherObject, callback) ->
      return switch arguments.length
        # Return Writable Stream
        when 1 then decryptStream(passphrase)
        # Return Promise
        when 2 then decryptPromise(passphrase, cipherObject)
        # Encrypt then call callback
        when 3 then decryptAsync(passphrase, cipherObject, callback)

The `encrypt` and `decrypt` functions are actually just wrappers for different ways to interact with the library.
- Passing in all 3 parameters results in typical Node callback behavior.
- Passing in 2 parameters but no callback returns a Promise.
- Passing in just 1 parameter returns a stream.

## Async Encrypt/Decrypt

    encryptAsync = (passphrase, plainfile, callback) ->
      # Generate a random passphrase salt
      salt = crypto.randomBytes(E.SALT_LENGTH)

### Arguments:
- *passphrase* (String):
  This is a password that YOU the user chooses. I would still recommend generating it randomly. Make it big.
  This is the ONLY thing that needs to be kept secret. The key, salt, iv etc can all be visible publicly, and should be
  saved and sent along with the encrypted message.
- *plainfile* (String or Buffer):
  This is the input to the `encrypt` function / output of the `decrypt` function.
- *cipherObject* (Object):
  This is the output of the `encrypt` function / input to the `decrypt` function.

## Derive an encryption key from the passphrase and salt

      crypto.pbkdf2 passphrase, salt, E.ITERATIONS, E.KEY_LENGTH, E.HASH_ALGORITHM, (err, key) ->
        return callback err if err?

Passwords stopped being useful by themselves a long time ago. They are just too short. So nowadays encryption is done
using "keys". That key is generated from a password using a key derivation function. However, most people choose
easy-to-guess passwords. This makes the encrypted file vulnerable to "dictionary" attacks where the attacker just tries
every password in an enormous list of commonly used passwords. To mitigate this, it must take long enough to derive
a key from a password that it is infeasible for the attacker to try every possible password. The amount of time it
takes to derive a key is controlled by the `ITERATIONS` parameter.

As an added layer of security, instead of reusing the raw password to derive the key, a random string is
combined with the password to ensure it is not in any existing dictionary attack table. That random string is called
a `salt`.

`crypto.pbkdf2` (Password-Based Key Derivation Function 2) takes the user supplied passphrase, salts it, and
applies the `HASH_ALGORITHM` an `ITERATIONS` number of times to generate a key of `KEY_LENGTH`.
This key is NOT saved, but can be recreated by someone who knows the passphrase, the salt, the key length, the
hash algorithm and number of iterations to use.

        # Generate a random 96-bit initialization vector
        iv = crypto.randomBytes(E.IV_LENGTH)
        # Create a symmetric cipher using the key and initialization vector
        cipher = crypto.createCipheriv E.CIPHER_ALGORITHM, key, iv

The actual `CIPHER_ALGORITHM` is a block cipher, meaning it breaks the file into blocks of equal size and encrypts each
block *using the results of the previous block*. How does it encrypt the first block then? That's what the
initialization vector is for. If it was the same every time, (say all zeros) that could potentially be exploited,
so instead it is generated as random bytes (so it is different EVERY time) and saved just like the salt is.

        # Stream the plainfile into the cipher
        cipher.end plainfile, (err) ->
          return callback err if err?
          # Read the encrypted text out of the cipher
          cipherfile = cipher.read()
          authtag = cipher.getAuthTag()
          # Create cipherObject result
          result = new CipherObject
            yael_version: pkg.version

The npm package version doubles as the CipherObject format / export file format version.

            cipherfile: cipherfile
            iv: iv
            salt: salt
            authtag: authtag

The cipherfile is the encrypted data. The salt and iv are needed to decrypt the cipherfile.
The authtag provides file integrity verification to detect file corruption.

            return_type: switch
              when typeof plainfile is 'string' then 'String'
              when plainfile instanceof Buffer then 'Buffer'
              else 'undefined'

Strings get automatically converted to buffers by the cipher, so we save the type information in `return_type`.
That way if plainfile was a string, decrypt can know to return a string instead of a buffer.

            details:
              CIPHER_ALGORITHM: E.CIPHER_ALGORITHM
              SALT_LENGTH: E.SALT_LENGTH
              IV_LENGTH: E.IV_LENGTH
              KEY_LENGTH: E.KEY_LENGTH
              HASH_ALGORITHM: E.HASH_ALGORITHM
              ITERATIONS: E.ITERATIONS

We output all these details for convenience. However, these details are redundant since we also store the yael_version.
(Because if you know which version of yael did the encryption, you know exactly what scheme was used.)

          # Return an object containing the result
          callback null, result

      # Return null because it's asynchronous
      return null

The decryption function is pretty much just the reverse of the encryption function. The only difference is we
check that the yael_version in the CipherObject is compatible with this version of YAEL.

    decryptAsync = (passphrase, cipherObject, callback) ->
      {yael_version, cipherfile, iv, salt, authtag, return_type} = cipherObject
      # Assert yael_version is compatible
      err = incompatibleVersion(yael_version)
      return callback err if err?
      # Generate an encryption key from the passphrase and salt
      crypto.pbkdf2 passphrase, salt, E.ITERATIONS, E.KEY_LENGTH, E.HASH_ALGORITHM, (err, key) ->
        return callback err if err?
        decipher = crypto.createDecipheriv E.CIPHER_ALGORITHM, key, iv
        decipher.setAuthTag authtag
        try
          decipher.end cipherfile, (err) ->
            return callback err if err?
            plainfile = decipher.read()
            # Restore original object's type
            plainfile = plainfile.toString() if return_type is 'String'
            callback null, plainfile
        catch err
          if err.message is "Unsupported state or unable to authenticate data"
            return callback new Error "Message Corrupted"
          return callback err if err?
      return null

## Promises

Some wrappers that promisify encryptAsync and decryptAsync:

    encryptPromise = (passphrase, plaintext) ->
      return new Promise (resolve, reject) ->
        encryptAsync passphrase, plaintext, (err, result) ->
          return reject(err) if err?
          return resolve(result)
    decryptPromise = (passphrase, cipherObject) ->
      return new Promise (resolve, reject) ->
        decryptAsync passphrase, cipherObject, (err, result) ->
          return reject(err) if err?
          return resolve(result)

## Syncronous Encrypt/Decrypt

    encryptSync = (passphrase, plainfile) ->
      return_type = switch
        when typeof plainfile is 'string' then 'String'
        when plainfile instanceof Buffer then 'Buffer'
        else 'undefined'
      if return_type is 'String'
        plainfile = new Buffer(plainfile, 'utf8')
      salt = crypto.randomBytes(E.SALT_LENGTH)
      key = crypto.pbkdf2Sync passphrase, salt, E.ITERATIONS, E.KEY_LENGTH, E.HASH_ALGORITHM
      iv = crypto.randomBytes(E.IV_LENGTH)
      cipher = crypto.createCipheriv E.CIPHER_ALGORITHM, key, iv
      cipherfile = Buffer.concat [cipher.update(plainfile), cipher.final()]
      authtag = cipher.getAuthTag()
      result = new CipherObject
        yael_version: pkg.version
        cipherfile: cipherfile
        iv: iv
        salt: salt
        authtag: authtag
        return_type: return_type
        details:
          CIPHER_ALGORITHM: E.CIPHER_ALGORITHM
          SALT_LENGTH: E.SALT_LENGTH
          IV_LENGTH: E.IV_LENGTH
          KEY_LENGTH: E.KEY_LENGTH
          HASH_ALGORITHM: E.HASH_ALGORITHM
          ITERATIONS: E.ITERATIONS
      return result

    decryptSync = (passphrase, cipherObject) ->
      {yael_version, cipherfile, iv, salt, authtag, return_type} = cipherObject
      # Assert yael_version is compatible
      err = incompatibleVersion(yael_version)
      throw err if err?
      key = crypto.pbkdf2Sync passphrase, salt, E.ITERATIONS, E.KEY_LENGTH, E.HASH_ALGORITHM
      decipher = crypto.createDecipheriv E.CIPHER_ALGORITHM, key, iv
      decipher.setAuthTag authtag
      try
        plainfile = Buffer.concat [decipher.update(cipherfile), decipher.final()]
        plainfile = plainfile.toString('utf8') if return_type is 'String'
        return plainfile
      catch err
        if err.message is "Unsupported state or unable to authenticate data"
          throw new Error "Message Corrupted"

## Backwards compatibility logic

- Patch updates are always compatible
- Minor updates are capable of reading files generated by older versions
- Major updates are incompatible with previous versions

    incompatibleVersion = (yael_version) ->
      # Assert yael_version is OK
      if not semver.valid(yael_version)?
        return new Error "cipherObject cannot be read because cipherObject.yael_version is not a valid semver"
      # Assert that the cipherObject was generated in a compatible file format
      if semver.major(yael_version) isnt semver.major(pkg.version)
        return new Error "cipherObject cannot be read because cipherObject.yael_version is incompatible with this version of yael"
      # Assert that the cipherObject was not generated by newer version file format
      if semver.minor(yael_version) > semver.minor(pkg.version)
        return new Error "cipherObject cannot be read because cipherObject.yael_version indicates the cipherObject was made by a newer version of yael"
      return null

Finally, we expose the following functions as the official API:

    module.exports =
      encrypt: encrypt
      encryptSync: encryptSync
      decrypt: decrypt
      decryptSync: decryptSync
      CipherObject: CipherObject
