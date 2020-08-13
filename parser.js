const cbor = require("cbor")
const base64url = require("base64url")
const coseToJwk = require("cose-to-jwk")
const jwkToPem = require("jwk-to-pem")

function parseClientData(buffer) {
  // Decode Buffer to utf-8
  const utf8Decoder = new TextDecoder("utf-8")
  const decodedClientData = utf8Decoder.decode(buffer)

  // Parse to JSON
  const clientDataObj = JSON.parse(decodedClientData)

  return clientDataObj
}

// Buffer format:
// rpIdHash:            byte index 0-31 : 32 bytes
// flags:               byte index 32 : 1 bytes
// signCount:           byte index 33-36: 4 bytes
// ----- Begin attestation data -----
// aaguid:              byte index 37-52: 16 bytes
// credentialIdLength:	byte index 53-54: 2 bytes
// credentialId:        byte index 55-(55+x-1): x bytes - need to get from credentialIdLength
// credentialPublicKey	byte index (55+x)-end: ? bytes
function parseAuthenticatorData(authData) {
  const dataView = new DataView(new ArrayBuffer(2))
  const idLenBytes = authData.slice(53, 55)
  idLenBytes.forEach((value, index) => dataView.setUint8(index, value))
  const credentialIdLength = dataView.getUint16()

  // get the credential ID
  const credentialId = authData.slice(55, 55 + credentialIdLength)

  // get the public key object
  const publicKeyBytes = authData.slice(55 + credentialIdLength)

  // conver public key to pem format
  const jwkFormattedPublicKey = coseToJwk(publicKeyBytes)
  const pemFormattedPublicKey = jwkToPem(jwkFormattedPublicKey)

  return {
    rpIdHash: authData.slice(0, 32),
    flags: authData.slice(32, 33),
    signCount: authData.slice(33, 37),
    aaguid: authData.slice(37, 53),
    credentialPublicKey: publicKeyBytes,
    jwkFormattedPublicKey,
    pemFormattedPublicKey,
  }
}

function parseAttestationObj(buffer) {
  // Decode from cose
  const decodedAttestationObject = cbor.decodeAllSync(buffer)[0]

  const { authData, fmt, attStmt } = decodedAttestationObject

  // Parsing authData
  const parsedAuthData = parseAuthenticatorData(authData)

  return { authData: parsedAuthData, fmt, attSmt }
}

module.exports = {
  parseAttestationObj,
}
