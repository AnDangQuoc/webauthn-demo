const cbor = require("cbor")
const base64url = require("base64url")
const coseToJwk = require("cose-to-jwk")
const jwkToPem = require("jwk-to-pem")
const asn1js = require("asn1js")
const pkijs = require("pkijs")

const Certificate = pkijs.Certificate

const { prettyStringify, oids } = require("./utils")

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

  // Parsing cert if have
  if (attStmt.x5c) {
    const pasredAttestationCertificate = parseAttestaionCertificate(attStmt.x5c)
    attStmt.parsedCert = pasredAttestationCertificate
  }

  return {
    authData: parsedAuthData,
    fmt,
    attStmt,
  }
}

function parseAttestaionCertificate(bufferArray) {
  const info = []
  for (const x5c of bufferArray) {
    const buffer = x5c.buffer.slice(
      x5c.byteOffset,
      x5c.byteOffset + x5c.byteLength
    )
    const parsed = asn1js.fromBER(buffer)
    const cert = new Certificate({ schema: parsed.result })
    const slice = {
      version: cert.version,
      serialNumber: Buffer.from(cert.serialNumber.valueBlock.valueHex).toString(
        "hex"
      ),
      signature: {
        algorithmId: oids[cert.signature.algorithmId],
        value: Buffer.from(cert.signatureValue.valueBlock.valueHex).toString(
          "hex"
        ),
      },
      issuer: cert.issuer.typesAndValues[0].value.valueBlock.value,
      notBefore: cert.notBefore.value,
      notAfter: cert.notAfter.value,
      subject: cert.subject.typesAndValues.map((v) => v.value.valueBlock.value),
      subjectPublicKeyInfo: cert.subjectPublicKeyInfo,
    }
    info.push(slice)
  }

  return info
}

// Parse data to base 64 to send to server
function publicKeyCredentialToJSON(pubKeyCred) {
  if (pubKeyCred instanceof Array) {
    let arr = []
    for (let i of pubKeyCred) arr.push(publicKeyCredentialToJSON(i))

    return arr
  }

  if (pubKeyCred instanceof ArrayBuffer) {
    return base64url.encode(pubKeyCred)
  }

  if (pubKeyCred instanceof Object) {
    let obj = {}

    for (let key in pubKeyCred) {
      obj[key] = publicKeyCredentialToJSON(pubKeyCred[key])
    }

    return obj
  }

  return pubKeyCred
}

module.exports = {
  parseAttestationObj,
  parseClientData,
  parseAttestaionCertificate,
}
