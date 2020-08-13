const express = require("express")
const utils = require("../utils")
const config = require("../config.json")
const base64url = require("base64url")
const router = express.Router()
const database = require("./db")
const {
  parseAttestationObject,
  parseAuthenticatorData,
} = require("./parser/output-parser")
const crypto = require("crypto")
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
  database[username] = {
    username: username,
    authrInfo: publicKeyCredential,
  }
  res.json({ status: "ok" })
})

router.post("/login/v2", (req, res) => {
  const { username, publicKeyCredential } = req.body
  const authrInfo = database[username].authrInfo
  // console.log(database[username])
  // console.log(authrInfo)

  // const attestation = parseAttestationObject(
  //   base64url.toBuffer(authrInfo.response.attestationObject)
  // )
  const authenticator = parseAuthenticatorData(
    base64url.toBuffer(publicKeyCredential.response.authenticatorData)
  )

  const data = Buffer.concat([
    base64url.toBuffer(publicKeyCredential.response.authenticatorData),
    utils.hash(base64url.toBuffer(publicKeyCredential.response.clientDataJSON)),
  ])

  const result = crypto
    .createVerify("SHA256")
    .update(data)
    .verify(authrInfo, publicKeyCredential.response.signature)

  console.log("AAAAAAA", result)
  res.json({ status: "ok", result })
})

router.post("/verify/v2", (request, response) => {
  let { username, webauthnResp } = request.body
  let clientData = JSON.parse(
    base64url.decode(webauthnResp.response.clientDataJSON)
  )
  console.log(webauthnResp)

  if (!database[username]) {
    database[username] = {
      authenticators: [],
    }
  }

  /* Check challenge... */
  // if (clientData.challenge !== request.session.challenge) {
  //   response.json({
  //     status: "failed",
  //     message: "Challenges don't match!",
  //   })
  // }

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
      database[username].authenticators.push(result.authrInfo)
      database[username].registered = true
    }
  } else if (webauthnResp.response.authenticatorData !== undefined) {
    /* This is get assertion */
    result = utils.verifyAuthenticatorAssertionResponse(
      webauthnResp,
      database[username].authenticators
    )
  } else {
    response.json({
      status: "failed",
      message: "Can not determine type of response!",
    })
  }
  console.log(result)

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

module.exports = router
