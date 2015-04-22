#!/usr/bin/env coffee
expect = require('chai').expect
crypto = require 'crypto'
yael = require '..'

describe 'Module API', ->
  it 'should load/exist', ->
    expect(yael).to.exist
  it 'should have encrypt() function', ->
    expect(yael.encrypt).to.be.a('function')
  it 'should have decrypt() function', ->
    expect(yael.decrypt).to.be.a('function')

describe 'Encryption tests', ->
  before ->
    global.plainbuffer = crypto.randomBytes(1024)
  it 'encrypt "Hello World!"', (done) ->
    yael.encrypt "my password", "Hello World!", (err, cipherObject) ->
      expect(err).to.be.null
      expect(cipherObject).to.exist
      expect(cipherObject.return_type).to.equal('String')
      global.cipherString = cipherObject
      done()
  it 'encrypt buffer', (done) ->
    yael.encrypt "asdf", plainbuffer, (err, cipherObject) ->
      expect(err).to.be.null
      expect(cipherObject).to.exist
      expect(cipherObject.return_type).to.equal('Buffer')
      global.cipherBuffer = cipherObject
      done()

  it 'encrypt "Hello World!" (Promise)', (done) ->
    yael.encrypt "my password", "Hello World!"
    .then (cipherObject) ->
      expect(cipherObject).to.exist
      expect(cipherObject.return_type).to.equal('String')
      global.cipherStringP = cipherObject
      done()
  it 'encrypt buffer (Promise)', (done) ->
    yael.encrypt "asdf", plainbuffer
    .then (cipherObject) ->
      expect(cipherObject).to.exist
      expect(cipherObject.return_type).to.equal('Buffer')
      global.cipherBufferP = cipherObject
      done()

describe 'Decryption tests', ->
  it 'decrypt "Hello World!"', (done) ->
    yael.decrypt "my password", cipherString, (err, plainfile) ->
      expect(err).to.be.null
      expect(plainfile).to.exist
      global.plainfile = plainfile
      done()
  it 'decrypt buffer', (done) ->
    yael.decrypt "asdf", cipherBuffer, (err, plainbuffer2) ->
      expect(err).to.be.null
      expect(plainbuffer2).to.exist
      global.plainbuffer2 = plainbuffer2
      done()

  it 'decrypt "Hello World!" (Promise)', (done) ->
    yael.decrypt "my password", cipherStringP
    .then (plainfile) ->
      expect(plainfile).to.exist
      global.plainfileP = plainfile
      done()
  it 'decrypt buffer (Promise)', (done) ->
    yael.decrypt "asdf", cipherBufferP
    .then (plainbuffer2) ->
      expect(plainbuffer2).to.exist
      global.plainbuffer2P = plainbuffer2
      done()

describe 'Correct output', ->
  it 'decrypted string output matches input', ->
    expect(plainfile).to.equal("Hello World!")
  it 'decrypted buffer output matches input', ->
    expect(plainbuffer).to.deep.equal(plainbuffer2)

  it 'decrypted string output matches input (Promise)', ->
    expect(plainfileP).to.equal("Hello World!")
  it 'decrypted buffer output matches input (Promise)', ->
    expect(plainbuffer).to.deep.equal(plainbuffer2P)

describe 'Catch authTag (file integrity) error', ->
  before ->
    # Manipulate first byte
    cf = cipherString.cipherfile
    cf[0] = cf[0] ^ cf[1]
    cf = cipherBuffer.cipherfile
    cf[0] = cf[0] ^ cf[1]
  it 'decrypt string', (done) ->
    yael.decrypt "my password", cipherString, (err, plainfile) ->
      expect(err).to.deep.equal(new Error "Message Corrupted")
      done()
  it 'decrypt buffer', (done) ->
    yael.decrypt "asdf", cipherBuffer, (err, plainbuffer) ->
      expect(err).to.deep.equal(new Error "Message Corrupted")
      done()
  it 'decrypt string (Promise)', (done) ->
    yael.decrypt "my password", cipherString
    .catch (err) ->
      expect(err).to.deep.equal(new Error "Message Corrupted")
      done()
  after ->
    # Undo manipulation of first byte
    cf = cipherString.cipherfile
    cf[0] = cf[0] ^ cf[1]
    cf = cipherBuffer.cipherfile
    cf[0] = cf[0] ^ cf[1]

describe 'Catch yael_version mismatch error', ->
  it 'major version change up', (done) ->
    cipherBuffer.yael_version = 'v2.0.0'
    yael.decrypt "asdf", cipherBuffer, (err, plainbuffer2) ->
      expect(err).to.deep.equal(new Error "cipherObject cannot be read because cipherObject.yael_version is incompatible with this version of yael")
      done()
  it 'major version change down', (done) ->
    cipherBuffer.yael_version = 'v0.0.0'
    yael.decrypt "asdf", cipherBuffer, (err, plainbuffer2) ->
      expect(err).to.deep.equal(new Error "cipherObject cannot be read because cipherObject.yael_version is incompatible with this version of yael")
      done()
  it 'minor version change up', (done) ->
    cipherBuffer.yael_version = 'v1.99.0'
    yael.decrypt "asdf", cipherBuffer, (err, plainbuffer2) ->
      expect(err).to.deep.equal(new Error "cipherObject cannot be read because cipherObject.yael_version indicates the cipherObject was made by a newer version of yael")
      done()
  it 'minor version change down', (done) ->
    cipherBuffer.yael_version = 'v1.0.0'
    yael.decrypt "asdf", cipherBuffer, (err, plainbuffer2) ->
      expect(err).to.be.null
      done()
  it 'patch version change up', (done) ->
    cipherBuffer.yael_version = 'v1.0.99'
    yael.decrypt "asdf", cipherBuffer, (err, plainbuffer2) ->
      expect(err).to.be.null
      done()
  it 'patch version change down', (done) ->
    cipherBuffer.yael_version = 'v1.0.0'
    yael.decrypt "asdf", cipherBuffer, (err, plainbuffer2) ->
      expect(err).to.be.null
      done()
  it 'major version change up (Promise)', (done) ->
    cipherBuffer.yael_version = 'v2.0.0'
    yael.decrypt "asdf", cipherBuffer
    .catch (err) ->
      expect(err).to.deep.equal(new Error "cipherObject cannot be read because cipherObject.yael_version is incompatible with this version of yael")
      done()
