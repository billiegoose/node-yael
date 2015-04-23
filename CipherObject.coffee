semver = require 'semver'

# TODO: Test entire file

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

class BufSlicer
  constructor: (@buf, @beg = 0, @end = 0)
  slice: (len) ->
    @beg = @end
    @end = if len? then @end + len else @buf.length
    return @buf[@beg...@end]

class CipherObject
  # Reserve properties
  yael_version: null
  cipherfile: null
  iv: null
  salt: null
  authtag: null
  return_type: 'undefined'
  details: null
  constructor: (o) ->
    console.log 'Construct CipherObject'
    switch
      when typeof o is 'object'
        console.log 'Hmmm.... what should this be. Options?'
      when typeof o is 'string'
        try json = JSON.parse(o)
        catch
          throw new Error "new CipherObject(String): Invalid JSON"
        json.cipherfile = str2buf json.cipherfile
        json.iv         = str2buf json.iv
        json.salt       = str2buf json.salt
        json.authtag    = str2buf json.authtag
        return json
      when o instanceof Buffer
        json = {}
        buf = new BufSlicer(o)
        [major, minor, patch] = buf.slice 3
        json.yael_version = major + '.' + minor + '.' + patch
        # TODO: Compare version number against package version. If older, use older parser.
        return_type = buf.slice 1
        json.return_type = switch return_type
          when 'S' then 'String'
          when 'B' then 'Buffer'
        SALT_LENGTH = 16
        IV_LENGTH = 12
        KEY_LENGTH = 32
        json =
          yael_version: yael_version
          return_type:  return_type
        json.salt = buf.slice SALT_LENGTH
        json.iv = buf.slice IV_LENGTH
        json.authtag = buf.slice AUTHTAG_LENGTH
        json.cipherfile = buf.slice()
        return json
      else
        return {}
  # Convert buffers to base64 strings
  # (following convention in json-buffer package for lack of better ideas)
  toString: ->
    JSON.stringify
      yael_version: @yael_version
      cipherfile:   buf2str @cipherfile
      iv:           buf2str @iv
      salt:         buf2str @salt
      authtag:      buf2str @authtag
      return_type:  @return_type
      details:      details
  # Export an unreadable binary blob of goo
  toBuffer: ->
    v = semver.parse(@ael_version)
    t = @return_type[0]
    Buffer.concat [
      new Buffer([v.major,v.minor,v.patch])
      new Buffer([t])
      cipherObject.salt
      cipherObject.iv
      cipherObject.authtag
      cipherObject.cipherfile
    ]
module.exports = CipherObject
