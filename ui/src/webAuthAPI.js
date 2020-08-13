export function initRegistration(body) {
  return fetch("/webauthn/register/v2/init", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  })
    .then((response) => response.json())
    .then((response) => {
      if (response.status !== "ok")
        throw new Error(
          `Server responed with error. The message is: ${response.message}`
        )

      return response
    })
}

export function initWebAuth() {
  return fetch("/webauthn/init", {
    method: "GET",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
  })
    .then((response) => response.json())
    .then((response) => {
      if (response.status !== "ok")
        throw new Error(
          `Server responed with error. The message is: ${response.message}`
        )

      return response
    })
}

export function register(body) {
  return fetch("/webauthn/register/v2", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  })
    .then((response) => response.json())
    .then((response) => {
      if (response.status !== "ok")
        throw new Error(
          `Server responed with error. The message is: ${response.message}`
        )

      return response
    })
}

export function login(body) {
  return fetch("/webauthn/login/v2", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  })
    .then((response) => response.json())
    .then((response) => {
      if (response.status !== "ok")
        throw new Error(
          `Server responed with error. The message is: ${response.message}`
        )

      return response
    })
}

export function verify(body) {
  return fetch("/webauthn/verify/v2", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  })
    .then((response) => response.json())
    .then((response) => {
      if (response.status !== "ok")
        throw new Error(
          `Server responed with error. The message is: ${response.message}`
        )

      return response
    })
}
