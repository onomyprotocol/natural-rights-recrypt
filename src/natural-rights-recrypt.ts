import { bufferToHex, hexToBuffer } from './hex-buffer'
import { TextEncoder, TextDecoder } from 'text-encoding-shim'
import { base64 } from './base64'

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

function replacer(_key: string, value: any) {
  if (value instanceof Uint8Array) {
    return bufferToHex(value)
  }
  if (value instanceof Buffer) {
    return bufferToHex(new Uint8Array(value))
  }

  if (value && value.type === 'Buffer') {
    return bufferToHex(new Uint16Array(value.data))
  }
  return value
}

function reviver(_key: string, value: any) {
  if (typeof value === 'string') {
    return hexToBuffer(value)
  }
  return value
}

function stringify(value: any) {
  return base64.btoa(JSON.stringify(value, replacer))
}

function parse(text: string) {
  return JSON.parse(base64.atob(text), reviver)
}

const encoding = 'hex'

interface KeyPair {
  readonly privKey: string
  readonly pubKey: string
}

export default function recryptApiToNaturalRights(RecryptApi: any) {
  return {
    serialize(obj: any) {
      return stringify(obj)
    },

    async cryptKeyGen() {
      const encryptionKeys = RecryptApi.generateKeyPair()
      const pubX = bufferToHex(encryptionKeys.publicKey.x)
      const pubY = bufferToHex(encryptionKeys.publicKey.y)

      return {
        privKey: bufferToHex(encryptionKeys.privateKey),
        pubKey: `${pubX}.${pubY}`
      }
    },

    async cryptTransformKeyGen(fromKeyPair: KeyPair, toPubKey: string, signKeyPair: KeyPair) {
      const [pubX, pubY] = toPubKey.split('.')

      return stringify(
        RecryptApi.generateTransformKey(
          hexToBuffer(fromKeyPair.privKey),
          {
            x: hexToBuffer(pubX),
            y: hexToBuffer(pubY)
          },
          hexToBuffer(signKeyPair.privKey)
        )
      )
    },

    async encrypt(pubKey: string, plaintext: string, signKeyPair: KeyPair) {
      const [pubX, pubY] = pubKey.split('.')
      let padded = plaintext

      while (padded.length < 384) padded += ' '

      const res = RecryptApi.encrypt(
        textEncoder.encode(padded),
        {
          x: hexToBuffer(pubX),
          y: hexToBuffer(pubY)
        },
        Buffer.from(signKeyPair.privKey, encoding)
      )

      return stringify(res)
    },

    async signKeyGen() {
      const signingKeys = RecryptApi.generateEd25519KeyPair()

      return {
        privKey: bufferToHex(signingKeys.privateKey),
        pubKey: bufferToHex(signingKeys.publicKey)
      }
    },

    async cryptTransform(transformKey: string, ciphertext: string, signKeyPair: KeyPair) {
      return stringify(
        RecryptApi.transform(
          parse(ciphertext),
          parse(transformKey),
          hexToBuffer(signKeyPair.privKey)
        )
      )
    },

    async decrypt(keyPair: KeyPair, ciphertext: string) {
      const result = RecryptApi.decrypt(parse(ciphertext), hexToBuffer(keyPair.privKey))

      return textDecoder.decode(result instanceof Buffer ? new Uint8Array(result) : result).trim()
    },

    async sign(keyPair: KeyPair, text: string) {
      return bufferToHex(RecryptApi.ed25519Sign(hexToBuffer(keyPair.privKey), Buffer.from(text)))
    },

    async verify(pubKey: string, signature: string, text: string) {
      return RecryptApi.ed25519Verify(
        hexToBuffer(pubKey),
        Buffer.from(text),
        hexToBuffer(signature)
      ) as boolean
    }
  }
}
