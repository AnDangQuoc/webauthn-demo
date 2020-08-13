const express = require("express")
const utils = require("../utils")
const config = require("../config.json")
const base64url = require("base64url")
const router = express.Router()
const database = require("./db")
const crypto = require("crypto")
const { v4: uuidv4 } = require("uuid")

const { parseAttestationObj } = require("../parser")
const { hash, verify } = require("../utilsV2")

router.post("/register", (request, response) => {
  if (!request.body || !request.body.username || !request.body.name) {
    response.json({
      status: "failed",
      message: "Request missing name or username field!",
    })

    return
  }

  let username = request.body.username
  let name = request.body.name

  if (database[username] && database[username].registered) {
    response.json({
      status: "failed",
      message: `Username ${username} already exists`,
    })

    return
  }

  database[username] = {
    name: name,
    registered: false,
    id: utils.randomBase64URLBuffer(),
    authenticators: [],
  }

  let challengeMakeCred = utils.generateServerMakeCredRequest(
    username,
    name,
    database[username].id
  )
  challengeMakeCred.status = "ok"

  request.session.challenge = challengeMakeCred.challenge
  request.session.username = username

  response.json(challengeMakeCred)
})

router.post("/login", (request, response) => {
  if (!request.body || !request.body.username) {
    response.json({
      status: "failed",
      message: "Request missing username field!",
    })

    return
  }

  let username = request.body.username

  if (!database[username] || !database[username].registered) {
    response.json({
      status: "failed",
      message: `User ${username} does not exist!`,
    })

    return
  }

  let getAssertion = utils.generateServerGetAssertion(
    database[username].authenticators
  )
  getAssertion.status = "ok"

  request.session.challenge = getAssertion.challenge
  request.session.username = username

  response.json(getAssertion)
})

router.post("/response", (request, response) => {
  if (
    !request.body ||
    !request.body.id ||
    !request.body.rawId ||
    !request.body.response ||
    !request.body.type ||
    request.body.type !== "public-key"
  ) {
    response.json({
      status: "failed",
      message:
        "Response missing one or more of id/rawId/response/type fields, or type is not public-key!",
    })

    return
  }
  // console.warn("AAAAAAA", request.body)

  let webauthnResp = request.body
  let clientData = JSON.parse(
    base64url.decode(webauthnResp.response.clientDataJSON)
  )

  /* Check challenge... */
  if (clientData.challenge !== request.session.challenge) {
    response.json({
      status: "failed",
      message: "Challenges don't match!",
    })
  }

  /* ...and origin */
  if (clientData.origin !== config.origin) {
    response.json({
      status: "failed",
      message: "Origins don't match!",
    })
  }

  let result
  if (webauthnResp.response.attestationObject !== undefined) {
    /* This is create cred */
    result = utils.verifyAuthenticatorAttestationResponse(webauthnResp)

    if (result.verified) {
      database[request.session.username].authenticators.push(result.authrInfo)
      database[request.session.username].registered = true
    }
  } else if (webauthnResp.response.authenticatorData !== undefined) {
    /* This is get assertion */
    result = utils.verifyAuthenticatorAssertionResponse(
      webauthnResp,
      database[request.session.username].authenticators
    )
  } else {
    response.json({
      status: "failed",
      message: "Can not determine type of response!",
    })
  }
  console.warn("BBBBBB", result)

  if (result.verified) {
    request.session.loggedIn = true
    response.json({ status: "ok" })
  } else {
    response.json({
      status: "failed",
      message: "Can not authenticate signature!",
    })
  }
})

router.get("/db", (req, res) => {
  res.json(database)
})

router.post("/register/v2", (req, res) => {
  const { username, name, publicKeyCredential } = req.body
  database[username].authenticateInfo = publicKeyCredential
  res.json({ status: "ok" })
})

router.post("/register/v2/init", (req, res) => {
  const { username } = req.body
  const challenge = uuidv4()
  const userId = uuidv4()

  database[username] = {
    username: username,
    userId: userId,
    challenge: challenge,
  }

  return res.json({
    status: "ok",
    userId: userId,
    challenge: challenge,
  })
})

router.post("/login/v2", (req, res) => {
  const { username } = req.body
  if (!database[username]) {
    return res.json({ status: "error", message: "user not registered" })
  }
  const authenticateInfo = database[username].authenticateInfo
  const challenge = database[username].challenge
  if (!authenticateInfo || !challenge) {
    return res.json({ status: "error", message: "user data corrupted" })
  }

  return res.json({
    status: "ok",
    rawId: authenticateInfo.rawId,
    challenge: challenge,
  })
})

router.post("/verify/v2", (request, response) => {
  const { username, publicKeyCredential } = req.body
  const authenticateInfo = database[username].authenticateInfo

  if (!authenticateInfo) {
    return res.json({ status: "error", message: "user not logged in" })
  }
  // Parse Attestation Object
  const bufferedAttestation = base64url.toBuffer(
    authenticateInfo.response.attestationObject
  )
  const attestationObject = parseAttestationObj(bufferedAttestation)

  database[username].assertInfo = publicKeyCredential
  database[username].parsedAttestation = attestationObject

  const bufferedAuthenticator = base64url.toBuffer(
    publicKeyCredential.response.authenticatorData
  )

  const hashedClientJSON = hash(
    base64url.toBuffer(publicKeyCredential.response.clientDataJSON)
  )

  const signedData = Buffer.concat([bufferedAuthenticator, hashedClientJSON])

  const bufferedSignature = base64url.toBuffer(
    publicKeyCredential.response.signature
  )
  const result = verify(
    signedData,
    bufferedSignature,
    attestationObject.authData.pemFormattedPublicKey
  )

  res.json({ status: "ok", result })
})

module.exports = router
