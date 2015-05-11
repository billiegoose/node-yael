semver = require 'semver'
E = require './constants'

# Convert buffers to base64 strings following the convention in the json-buffer package for lack of a better idea.
buf2str = (buf, enc='base64') ->
  if not Buffer.isEncoding(enc) then throw new Error "CipherObject: buf2str Buffer.isEncoding('#{enc}') returned false."
  return ":#{enc}:#{buf.toString(enc)}"
str2buf = (str) ->
  m = str.match /^:(.*):/
  if not m? then throw new Error "CipherObject: str2buf run on string but no :encoding: found at start"
  enc = m[1]
  if not Buffer.isEncoding(enc) then throw new Error "CipherObject: str2buf run on string with encoding :#{enc}: but Buffer.isEncoding('#{enc}') returned false."
  str = str[m[0].length...]
  return new Buffer(str, enc)

# Pretend buffers are sequential access instead of random access.
class BufSlicer
  constructor: (@buf, @beg = 0, @end = 0) ->
  slice: (len) ->
    @beg = @end
    @end = if len? then @end + len else @buf.length
    return @buf[@beg...@end]

class CipherObject
  constructor: (o) ->
    switch
      when o instanceof Buffer
        return @fromBuffer o
      when typeof o is 'string'
        return @fromString o
      when typeof o is 'object'
        # Shallow copy
        @[p] = o[p] for p of o when typeof o[p] isnt 'function'
  # Export as a JSON string
  toString: ->
    JSON.stringify
      yael_version: @yael_version
      cipherfile:   buf2str @cipherfile
      iv:           buf2str @iv
      salt:         buf2str @salt
      authtag:      buf2str @authtag
      return_type:  @return_type
      details:      @details
  fromString: (o) ->
    try json = JSON.parse(o)
    catch
      throw new Error "CipherObject.fromString: Invalid JSON"
    this[p] = json[p] for p of json
    @cipherfile = str2buf @cipherfile
    @iv         = str2buf @iv
    @salt       = str2buf @salt
    @authtag    = str2buf @authtag
    return this
  # Export an unreadable binary blob of goo
  toBuffer: ->
    v = semver.parse(@yael_version)
    t = @return_type[0]
    Buffer.concat [
      new Buffer([v.major,v.minor,v.patch])
      new Buffer(t)
      @salt
      @iv
      @authtag
      @cipherfile
    ]
  fromBuffer: (o) ->
    buf = new BufSlicer(o)
    [major, minor, patch] = buf.slice 3
    @yael_version = major + '.' + minor + '.' + patch
    # TODO: Compare version number against package version. If older, use older parser.
    return_type = buf.slice 1
    @return_type = switch return_type.toString()
      when 'S' then 'String'
      when 'B' then 'Buffer'
    @salt = buf.slice E.SALT_LENGTH
    @iv = buf.slice E.IV_LENGTH
    @authtag = buf.slice E.AUTHTAG_LENGTH
    @cipherfile = buf.slice()
    @details =
      CIPHER_ALGORITHM: E.CIPHER_ALGORITHM
      SALT_LENGTH: E.SALT_LENGTH
      IV_LENGTH: E.IV_LENGTH
      KEY_LENGTH: E.KEY_LENGTH
      HASH_ALGORITHM: E.HASH_ALGORITHM
      ITERATIONS: E.ITERATIONS

    return @

module.exports = CipherObject
