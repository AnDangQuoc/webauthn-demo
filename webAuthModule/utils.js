const crypto = require("crypto")

const hash = (buffer) => {
  return crypto.createHash("sha256").update(buffer).digest()
}

module.exports = {
  hash,
  verify,
}
