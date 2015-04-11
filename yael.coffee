#!/usr/bin/env coffee
# -- Yet Another Encryption Library

crypto = require 'crypto'

###
A brief explanation.
passphrase:
  This is a password that YOU the user chooses. I would still recommend generating it randomly. Make it big.
  This is the ONLY thing that needs to be kept secret.
salt:
  This is a random string that is appended to the user chosen passphrase to ensure that
  the encrypted text can't be quickly un-encrypted by using a rainbow table.
pbkdf2:
  Password-Based Key Derivation Function 2. An algorithm used to turn the passphrase and salt into a much
  larger piece of text called the key.
key:
  This is the data that is actually used to encrypt and decrypt the text.
initialization vector:
  This is a large random byte array used to initialize the encryption algorithm. It can be public, but it needs
  to be different every time the encryption key is used. Hence, random.
plainfile:
  This is the file given to the `encrypt` function and returned by the `decrypt` function.
cipherfile:
  This is the file returned by the `encrypt` function and given to the `decrypt` function.
cipher:
  The actual encryption algorithm.
###

algorithm = 'aes-256-gcm'
# Note: AES-256-GCM is very picky about these numbers. Took me a while to get them right.
SALT_LENGTH = 16
IV_LENGTH = 12
KEY_LENGTH = 32
# This one is more arbitrary
ITERATIONS = 1000
HMAC = 'sha256'

module.exports =
  encrypt: (passphrase, plainfile, callback) ->
    # Generate a random passphrase salt
    salt = crypto.randomBytes(SALT_LENGTH)
    # Generate a random 96-bit initialization vector
    iv = crypto.randomBytes(IV_LENGTH)
    # Derive an encryption key from the passphrase and salt
    crypto.pbkdf2 passphrase, salt, ITERATIONS, KEY_LENGTH, HMAC, (err, key) ->
      return callback err if err?
      # Create a symmetric cipher using the key and initialization vector
      cipher = crypto.createCipheriv algorithm, key, iv
      # Stream the plainfile into the cipher
      cipher.end plainfile, (err) ->
        return callback err if err?
        # Read the encrypted text out of the cipher
        cipherfile = cipher.read()
        authtag = cipher.getAuthTag()
        # Return an object containing the result
        callback null,
          cipherfile: cipherfile
          iv: iv
          salt: salt
          authtag: authtag
          yael: '0.0.1'
  decrypt: (passphrase, cipherObject, callback) ->
    {cipherfile, iv, salt, authtag} = cipherObject
    # Generate an encryption key from the passphrase and salt
    crypto.pbkdf2 passphrase, salt, ITERATIONS, KEY_LENGTH, HMAC, (err, key) ->
      return callback err if err?
      decipher = crypto.createDecipheriv algorithm, key, iv
      decipher.setAuthTag authtag
      try
        plainfile = decipher.update cipherfile
        plainfile += decipher.final()
      catch err
        if err.message is "Unsupported state or unable to authenticate data"
          return callback new Error "Message Corrupted"
        return callback err if err?
      callback null, plainfile
  test: ->
    module.exports.encrypt "my password", "Hello World!", (err, cipherObject) ->
      console.log err, cipherObject
      # cipherObject.cipherfile[0] = 0
      module.exports.decrypt "my password", cipherObject, (err, plainfile) ->
        return console.log err if err?
        console.log plainfile.toString()
  test2: ->
    fs.createReadStream('helloworld.txt')
    .pipe(module.exports.encrypt("my password"))
    .pipe(module.exports.decrypt("my password"))
    .pipe(process.stdout)
