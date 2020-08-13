const crypto = require("crypto")

const verifySignature = (data, signature, publicKey) => {
  return crypto.createVerify("sha256").update(data).verify(publicKey, signature)
}

module.exports = {
  verifySignature,
}
