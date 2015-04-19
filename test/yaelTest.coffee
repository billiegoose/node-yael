#!/usr/bin/env coffee

expect = require('chai').expect
crypto = require 'crypto'
yael = require '..'

describe 'Module', ->
  it 'should load/exist', ->
    expect(yael).to.exist
  it 'should have encrypt() function', ->
    expect(yael.encrypt).to.be.a('function')
  it 'should have decrypt() function', ->
    expect(yael.decrypt).to.be.a('function')

describe 'Encrypt string', ->
  it 'encrypt "Hello World!"', (done) ->
    yael.encrypt "my password", "Hello World!", (err, cipherObject) ->
      return done err if err?
      expect(cipherObject).to.exist
      global.cipherObject = cipherObject
      done()
  it 'decrypt "Hello World!"', (done) ->
    yael.decrypt "my password", cipherObject, (err, plainfile) ->
      return done err if err?
      expect(plainfile).to.exist
      global.plainfile = plainfile
      done()
  it 'decrypted output matches input', ->
    expect(plainfile.toString()).to.equal("Hello World!")

describe 'Encrypt random buffer', ->
  before ->
    global.plainbuffer = crypto.randomBytes(1024)
  it 'encrypt buffer', (done) ->
    yael.encrypt "asdf", plainbuffer, (err, cipherObject) ->
      return done err if err?
      expect(cipherObject).to.exist
      global.cipherObject = cipherObject
      done()
  it 'decrypt buffer', (done) ->
    yael.decrypt "asdf", cipherObject, (err, plainbuffer2) ->
      return done err if err?
      expect(plainbuffer2).to.exist
      global.plainbuffer2 = plainbuffer2
      done()
  it 'decrypted output matches input', ->
    expect(plainbuffer).to.deep.equal(plainbuffer2)

describe 'Catch authTag (file integrity) error', ->
  before ->
    # Manipulate first byte
    cf = cipherObject.cipherfile
    cf[0] = cf[0] ^ cf[1]
  it 'decrypt buffer', (done) ->
    yael.decrypt "asdf", cipherObject, (err, plainbuffer2) ->
      expect(err).to.deep.equal(new Error "Message Corrupted")
      done()

  # test2: ->
  #   fs.createReadStream('README.md')
  #   .pipe(module.exports.encrypt("my password"))
  #   .pipe(module.exports.decrypt("my password"))
  #   .pipe(process.stdout)
