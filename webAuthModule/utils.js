const crypto = require("crypto")

const hash = (buffer) => {
  return crypto.createHash("sha256").update(buffer).digest()
}

function prettyStringify(object) {
  return JSON.stringify(object, null, 2)
}

const oids = {
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
}

module.exports = {
  hash,
  prettyStringify,
  oids,
}
