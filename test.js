const crypto = require("crypto")
const base64url = require("base64url")
const cbor = require("cbor")
const coseToJwk = require("cose-to-jwk")
const jwkToPem = require("jwk-to-pem")

const attestationObject =
  "o2NmbXRlYXBwbGVnYXR0U3RtdKJjYWxnJmN4NWOCWQJHMIICQzCCAcmgAwIBAgIGAXPlan3sMAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwODEzMDExMzQ4WhcNMjAwODE0MDEyMzQ4WjCBkTFJMEcGA1UEAwxANzYyZGVkYzZjYzYyZDkwMGJmMDVhOTA5YmJiNTEzMGY2N2Q0ZjM3NGIzYjZlOGFlNzVmN2VmNWY4ZDZiNGY4OTEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATPCpcst-aKu66kIHRK64ge2K5kTvF0mxHxfG2WQU1zG7VjhcZU2M9HxatrwnG5C8fy0psyHfTrz4RKRRwvgBM0o1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIPjWIeqIEFc-PMYidPRUA5ldSuGdXiH9hC008hZwu12oMAoGCCqGSM49BAMCA2gAMGUCMQDlBfBF5nySqJjJz3_yuP1VPMv7bzkBijw22FtfCw8eAY-4RnNC4DxcssxWMO3vErYCMD3FP7gHGiLxTikuPN3EJ1Oc50T7gYFv0tZ1yQuc5IsAXF9IMmdU0BvSC87ifw7ZEFkCODCCAjQwggG6oAMCAQICEFYlU5XHp_tA6-Io2CYIU7YwCgYIKoZIzj0EAwMwSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM4MDFaFw0zMDAzMTMwMDAwMDBaMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASDLocvJhSRgQIlufX81rtjeLX1Xz_LBFvHNZk0df1UkETfm_4ZIRdlxpod2gULONRQg0AaQ0-yTREtVsPhz7_LmJH-wGlggb75bLx3yI3dr0alruHdUVta-quTvpwLJpGjZjBkMBIGA1UdEwEB_wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUJtdk2cV4wlpn0afeaxLQG2PxxtcwHQYDVR0OBBYEFOuugsT_oaxbUdTPJGEFAL5jvXeIMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEA3YsaNIGl-tnbtOdle4QeFEwnt1uHakGGwrFHV1Azcifv5VRFfvZIlQxjLlxIPnDBAjAsimBE3CAfz-Wbw00pMMFIeFHZYO1qdfHrSsq-OM0luJfQyAW-8Mf3iwelccboDgdoYXV0aERhdGFYmHG0E2gvzptU8q_W7-M2e1-nONmozTn0VVmr3c2DTo8-RQAAAAAAAAAAAAAAAAAAAAAAAAAAABRR-YfFRKT4rjcY_uqoEg6VNn2g_KUBAgMmIAEhWCDPCpcst-aKu66kIHRK64ge2K5kTvF0mxHxfG2WQU1zGyJYILVjhcZU2M9HxatrwnG5C8fy0psyHfTrz4RKRRwvgBM0"

const clientDataJSON =
  "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQnJVYll0bG8yLUV5M2RXMmhQLUptM0JJZnJHX3h4eXZ2ZVVBVGtMQ2ZUMCIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG5wbGF5Lmhlcm9rdWFwcC5jb20ifQ"

const authenticatorData = "cbQTaC_Om1Tyr9bv4zZ7X6c42ajNOfRVWavdzYNOjz4FAAAAAA"

const signature =
  "MEYCIQC7qdksH71CxqtqYI7PivuxnSIhzxC5uQUl2AQZi8PqaAIhAKjjr2r2iat0VHjJ3apF-S8cnOL2QKx3NC2O0BubeORe"
let parseMakeCredAuthData = (buffer) => {
  let rpIdHash = buffer.slice(0, 32)
  buffer = buffer.slice(32)
  let flagsBuf = buffer.slice(0, 1)
  buffer = buffer.slice(1)
  let flags = flagsBuf[0]
  let counterBuf = buffer.slice(0, 4)
  buffer = buffer.slice(4)
  let counter = counterBuf.readUInt32BE(0)
  let aaguid = buffer.slice(0, 16)
  buffer = buffer.slice(16)
  let credIDLenBuf = buffer.slice(0, 2)
  buffer = buffer.slice(2)
  let credIDLen = credIDLenBuf.readUInt16BE(0)
  let credID = buffer.slice(0, credIDLen)
  buffer = buffer.slice(credIDLen)
  let COSEPublicKey = buffer

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credID,
    COSEPublicKey,
  }
}

let parseGetAssertAuthData = (buffer) => {
  let rpIdHash = buffer.slice(0, 32)
  buffer = buffer.slice(32)
  let flagsBuf = buffer.slice(0, 1)
  buffer = buffer.slice(1)
  let flags = flagsBuf[0]
  let counterBuf = buffer.slice(0, 4)
  buffer = buffer.slice(4)
  let counter = counterBuf.readUInt32BE(0)

  return { rpIdHash, flagsBuf, flags, counter, counterBuf }
}

let hash = (data) => {
  return crypto.createHash("SHA256").update(data).digest()
}

let COSEECDHAtoPKCS = (COSEPublicKey) => {
  /* 
         +------+-------+-------+---------+----------------------------------+
         | name | key   | label | type    | description                      |
         |      | type  |       |         |                                  |
         +------+-------+-------+---------+----------------------------------+
         | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
         |      |       |       | tstr    | the COSE Curves registry         |
         |      |       |       |         |                                  |
         | x    | 2     | -2    | bstr    | X Coordinate                     |
         |      |       |       |         |                                  |
         | y    | 2     | -3    | bstr /  | Y Coordinate                     |
         |      |       |       | bool    |                                  |
         |      |       |       |         |                                  |
         | d    | 2     | -4    | bstr    | Private key                      |
         +------+-------+-------+---------+----------------------------------+
      */

  let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0]
  let tag = Buffer.from([0x04])
  let x = coseStruct.get(-2)
  let y = coseStruct.get(-3)

  return Buffer.concat([tag, x, y])
}

let ASN1toPEM = (pkBuffer) => {
  if (!Buffer.isBuffer(pkBuffer))
    throw new Error("ASN1toPEM: pkBuffer must be Buffer.")

  let type
  if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
    /*
              If needed, we encode rawpublic key to ASN structure, adding metadata:
              SEQUENCE {
                SEQUENCE {
                   OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                   OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
                }
                BITSTRING <raw public key>
              }
              Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
          */

    pkBuffer = Buffer.concat([
      new Buffer.from(
        "3059301306072a8648ce3d020106082a8648ce3d030107034200",
        "hex"
      ),
      pkBuffer,
    ])

    type = "PUBLIC KEY"
  } else {
    type = "CERTIFICATE"
  }

  let b64cert = pkBuffer.toString("base64")

  let PEMKey = ""
  for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
    let start = 64 * i

    PEMKey += b64cert.substr(start, 64) + "\n"
  }

  PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`

  return PEMKey
}

let verifySignature = (signature, data, publicKey) => {
  return crypto
    .createVerify("SHA256")
    .update(data)
    .verify(publicKey, signature, "base64")
}

let attestationBuffer = base64url.toBuffer(attestationObject)

// const { parseAttestationObject } = require("./ui/src/utils/output-parser")

// const a = parseAttestationObject(attestationBuffer)
// console.log(a)
console.log(cbor.decodeAllSync(attestationBuffer))
let ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0]
let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData)
// console.log(authrDataStruct)

let clientDataHash = hash(base64url.toBuffer(clientDataJSON))

let reservedByte = Buffer.from([0x00])
let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)

console.log(coseToJwk(authrDataStruct.COSEPublicKey))
console.log(jwkToPem(coseToJwk(authrDataStruct.COSEPublicKey)))
const b = jwkToPem(coseToJwk(authrDataStruct.COSEPublicKey))
// console.log(publicKey)

let authenticatorDataBuffer = base64url.toBuffer(authenticatorData)

let authenticatorDataStruct = parseGetAssertAuthData(authenticatorDataBuffer)

let signatureBase = Buffer.concat([
  authenticatorDataStruct.rpIdHash,
  authenticatorDataStruct.flagsBuf,
  authenticatorDataStruct.counterBuf,
  clientDataHash,
])

// let signedData = Buffer.concat([authenticatorDataBuffer, clientDataHash])

// // publicKey = ASN1toPEM(base64url.toBuffer(publicKey))

// publicKey = ASN1toPEM(publicKey)

// console.log(publicKey)

let signatureToVerify = base64url.toBuffer(signature)

const result = verifySignature(signatureToVerify, signatureBase, b)

console.log(result)

const result2 = verifySignature(signature, base64url.encode(signatureBase), b)
console.log(result2)

// const { parseAttestationObject } = require("./routes/parser/output-parser")

// const a =
//   "o2NmbXRlYXBwbGVnYXR0U3RtdKJjYWxnJmN4NWOCWQJIMIICRDCCAcmgAwIBAgIGAXPjXJOBMAoGCCqGSM49BAMCMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwODEyMTUzOTIxWhcNMjAwODEzMTU0OTIxWjCBkTFJMEcGA1UEAwxAMjNiMDRmOGRlY2Q4NjU2MWM4M2ZlMGNiYTA4Yjc1MDIwNzhkZmM1ZjlhODg1MmFmZDk3OTRkYzFjY2Q3NTRkMjEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATC8zhW2GLgbwdtW8vUozNnqLNAD1JGfkjXUHqP7688ZyvEUUFJO4zSJ8ANCJBwCgM8DXKwV2U2Wkd-7aW9wf6Qo1UwUzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIE8DAzBgkqhkiG92NkCAIEJjAkoSIEIDWGkqJ3zTSkPAswS46t5za6V-ZJ2yQA-jV3bxXe8xHCMAoGCCqGSM49BAMCA2kAMGYCMQDxAw-0CRJJ2rsy1bxCUhool1H-KgaUKZakmIUWruaRjqUeW2zbhUslAx53KFrFBZMCMQCm6XQs4M0jjCjakujndNDoULW0NQq8dcOvfMK8P2ZtHpWpu1tGUnQc517elUDjvk1ZAjgwggI0MIIBuqADAgECAhBWJVOVx6f7QOviKNgmCFO2MAoGCCqGSM49BAMDMEsxHzAdBgNVBAMMFkFwcGxlIFdlYkF1dGhuIFJvb3QgQ0ExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgzODAxWhcNMzAwMzEzMDAwMDAwWjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgy6HLyYUkYECJbn1_Na7Y3i19V8_ywRbxzWZNHX9VJBE35v-GSEXZcaaHdoFCzjUUINAGkNPsk0RLVbD4c-_y5iR_sBpYIG--Wy8d8iN3a9Gpa7h3VFbWvqrk76cCyaRo2YwZDASBgNVHRMBAf8ECDAGAQH_AgEAMB8GA1UdIwQYMBaAFCbXZNnFeMJaZ9Gn3msS0Btj8cbXMB0GA1UdDgQWBBTrroLE_6GsW1HUzyRhBQC-Y713iDAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAN2LGjSBpfrZ27TnZXuEHhRMJ7dbh2pBhsKxR1dQM3In7-VURX72SJUMYy5cSD5wwQIwLIpgRNwgH8_lm8NNKTDBSHhR2WDtanXx60rKvjjNJbiX0MgFvvDH94sHpXHG6A4HaGF1dGhEYXRhWJhxtBNoL86bVPKv1u_jNntfpzjZqM059FVZq93Ng06PPkUAAAAAAAAAAAAAAAAAAAAAAAAAAAAUarSI5k0wWFenVGNk3lKX01UXiGClAQIDJiABIVggwvM4Vthi4G8HbVvL1KMzZ6izQA9SRn5I11B6j--vPGciWCArxFFBSTuM0ifADQiQcAoDPA1ysFdlNlpHfu2lvcH-kA"

// console.log(parseAttestationObject(base64url.toBuffer(a)))
