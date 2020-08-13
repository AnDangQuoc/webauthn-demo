import React from "react"
import { Card, Form, Input, Button, message, Tabs } from "antd"
import { JsonEditor as Editor } from "jsoneditor-react"
import "jsoneditor-react/es/editor.min.css"

import base64url from "base64url"

import {
  register,
  login,
  initRegistration,
  verify,
  initWebAuth,
} from "./webAuthAPI"

import { publicKeyCredentialToJSON } from "./utils"

const { TabPane } = Tabs

const layout = {
  labelCol: { span: 8 },
  wrapperCol: { span: 16 },
}
const tailLayout = {
  wrapperCol: { offset: 8, span: 16 },
}

class App extends React.Component {
  state = { challenge: "", userId: "" }
  async componentDidMount() {
    const a = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
    if (!a) {
      message.error("Webauthnn not support")
    }
    const storeWebAuth = localStorage.getItem("webAuthn")
    const webAuthId = localStorage.getItem("webAuthId") || null

    if (!storeWebAuth) {
      try {
        const res = await initWebAuth()
        localStorage.setItem(
          "webAuthn",
          JSON.stringify({ challenge: res.challenge, userId: res.userId })
        )
        this.setState({
          challenge: res.challenge,
          userId: res.userId,
          webAuthId,
        })
      } catch (error) {
        message.error(error.message)
      }
    } else {
      const parsedData = JSON.parse(storeWebAuth)
      this.setState({
        challenge: parsedData.challenge,
        userId: parsedData.userId,
        webAuthId,
      })
    }
    window.devState = () => {
      console.log(this.state)
    }
  }

  createWebauthConfig(username, displayName) {
    const { challenge, userId } = this.state
    const options = {
      publicKey: {
        challenge: Uint8Array.from(challenge, (c) => c.charCodeAt(0)),

        rp: {
          name: "Webauthn Play",
          id: "webauthnplay.herokuapp.com",
        },

        user: {
          id: Uint8Array.from(userId, (c) => c.charCodeAt(0)),
          name: username,
          displayName: displayName,
        },

        attestation: "direct",

        authenticatorSelection: { authenticatorAttachment: "platform" },
        pubKeyCredParams: [
          {
            type: "public-key",
            alg: -7, // "ES256" IANA COSE Algorithms registry
          },
        ],
      },
    }

    return options
  }

  createWebauthGetConfig() {
    const { challenge, webAuthId } = this.state
    return {
      publicKey: {
        challenge: Uint8Array.from(challenge, (c) => c.charCodeAt(0)),
        allowCredentials: [
          {
            type: "public-key",
            id: base64url.toBuffer(webAuthId),
            transports: ["usb", "ble", "nfc", "internal"],
          },
        ],
      },
    }
  }

  handleRegister = async (values) => {
    const { username, name = "auto" } = values
    const { userId, challenge } = this.state
    if (!username || !name) {
      message.error("Name or username is missing!")
      return
    }

    try {
      const options = this.createWebauthConfig(username, name)
      const createCredentialResponse = await navigator.credentials.create(
        options
      )
      const jsonBody = publicKeyCredentialToJSON(createCredentialResponse)
      await register({
        username,
        name,
        publicKeyCredential: jsonBody,
        userId,
        challenge,
      })

      localStorage.setItem("webAuthId", jsonBody.rawId)
      this.setState({ webAuthId: jsonBody.rawId })
      message.success("Registered")
    } catch (error) {
      message.error(error.message)
    }
  }

  handleLogin = async (values) => {
    let username = values.username2

    if (!username) {
      message.error("Username is missing!")
      return
    }

    try {
      const options = this.createWebauthGetConfig()

      const getCredentialResponse = await navigator.credentials.get(options)

      const jsonBody = publicKeyCredentialToJSON(getCredentialResponse)

      const verifyResult = await verify({
        username,
        publicKeyCredential: jsonBody,
      })

      if (verifyResult.result) {
        message.success("Verified")
      } else {
        message.error("Not Verified")
      }
    } catch (error) {
      message.error(error.message)
    }
  }

  render() {
    return (
      <div className="card-container">
        <Card>
          <Tabs type="card">
            <TabPane tab="Register" key="1">
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Form
                  onFinish={this.handleRegister}
                  {...layout}
                  id="form_register"
                >
                  <Form.Item
                    label="User Name"
                    name="username"
                    rules={[
                      {
                        required: true,
                        message: "Please input your username!",
                      },
                    ]}
                  >
                    <Input></Input>
                  </Form.Item>
                  <Form.Item
                    label="Name"
                    name="name"
                    rules={[
                      { required: true, message: "Please input your name!" },
                    ]}
                  >
                    <Input></Input>
                  </Form.Item>
                  <Form.Item {...tailLayout}>
                    <Button
                      type="primary"
                      htmlType="submit"
                      form="form_register"
                    >
                      Register
                    </Button>
                  </Form.Item>
                </Form>
              </div>
            </TabPane>
            <TabPane tab="Login" key="2">
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Form onFinish={this.handleLogin} id="form_update">
                  <Form.Item
                    label="User Name"
                    name="username2"
                    rules={[
                      {
                        required: true,
                        message: "Please input your username!",
                      },
                    ]}
                  >
                    <Input></Input>
                  </Form.Item>
                  <Form.Item {...tailLayout}>
                    <Button type="primary" htmlType="submit" form="form_update">
                      Login
                    </Button>
                  </Form.Item>
                </Form>
              </div>
            </TabPane>
          </Tabs>
        </Card>
      </div>
    )
  }
}
export default App
