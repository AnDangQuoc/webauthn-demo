const crypto = require("crypto")
const { create } = require("domain")

const hash = (buffer) => {
  return crypto.createHash("sha256").update(buffer).digest()
}

const verify = (data, signature, publicKey) => {
  return crypto.createVerify("sha256").update(data).verify(publicKey, signature)
}

module.exports = {
  hash,
  verify,
}
