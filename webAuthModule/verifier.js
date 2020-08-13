const crypto = require("crypto")
const { parseClientData } = require("./")

const verifySignature = (data, signature, publicKey) => {
  return crypto.createVerify("sha256").update(data).verify(publicKey, signature)
}

const verifyClientJSON = (clientData, challenge, origin) => {
  if (typeof clientData !== "object") {
    throw new Error("Please parse data to object before verify")
  }

  // Check if challenge match
  if (clientData.challenge !== challenge) {
    throw new Error("Challenge is not correct")
  }

  // Check if origin is allowed
  if (clientData.origin !== origin) {
    throw new Error("Invalid origin")
  }
  return
}

module.exports = {
  verifySignature,
}
