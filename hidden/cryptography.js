const splitChunks = (str, chunkSize) => {
  const result = []
  for (let i = 0; i < str.length; i += chunkSize) {
    result.push(str.substr(i, chunkSize))
  }
  return result
}

const serializeUint8Array = (arr) => [...arr].map(btoa).join('')

const deserializeUint8Array = (str) => new Uint8Array(splitChunks(str, 4).map(atob))

const generateKey = () => window.crypto.subtle.generateKey(
  {
    name: "AES-GCM",
    length: 128,
  },
  true, ["encrypt", "decrypt"],
)

const exportKey = async (key) => {
  let exportedKey = await window.crypto.subtle.exportKey("raw", key)
  exportedKey = new Uint8Array(exportedKey)
  return serializeUint8Array(exportedKey)
}

const importKey = async (key) => {
  const deserializedKey = deserializeUint8Array(key)

  return window.crypto.subtle.importKey("raw", deserializedKey, "AES-GCM", true, [
    "encrypt",
    "decrypt",
  ])
}

const encrypt = async (message, key) => {
  const iv = window.crypto.getRandomValues(new Uint8Array(16))
  const textEncoder = new TextEncoder()

  const encryptedMessage = window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, textEncoder.encode(message))

  const serializedMessage = serializeUint8Array(new Uint8Array(await encryptedMessage))
  return { message: serializedMessage, iv: serializeUint8Array(iv) }
}

const decrypt = async (message, key, iv) => {
  const textDecoder = new TextDecoder()

  return textDecoder.decode(
    await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: deserializeUint8Array(iv) },
      key,
      deserializeUint8Array(message).buffer
    )
  )
}

if (typeof window !== "object") {
  module.exports = {decrypt, encrypt, generateKey, importKey, exportKey}
}