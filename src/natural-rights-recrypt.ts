import * as JSON from 'buffer-json'

const encoding = 'hex'

interface KeyPair {
  readonly privKey: string
  readonly pubKey: string
}

export default function recryptApiToNaturalRights(RecryptApi: any) {
  return {
    async cryptKeyGen() {
      const encryptionKeys = RecryptApi.generateKeyPair()
      const pubX = encryptionKeys.publicKey.x.toString(encoding)
      const pubY = encryptionKeys.publicKey.y.toString(encoding)

      return {
        privKey: encryptionKeys.privateKey.toString(encoding) as string,
        pubKey: `${pubX}.${pubY}`
      }
    },

    async cryptTransformKeyGen(fromKeyPair: KeyPair, toPubKey: string, signKeyPair: KeyPair) {
      const [pubX, pubY] = toPubKey.split('.')

      return JSON.stringify(
        RecryptApi.generateTransformKey(
          Buffer.from(fromKeyPair.privKey, encoding),
          {
            x: Buffer.from(pubX, encoding),
            y: Buffer.from(pubY, encoding)
          },
          Buffer.from(signKeyPair.privKey, encoding)
        )
      ) as string
    },

    async encrypt(pubKey: string, plaintext: string, signKeyPair: KeyPair) {
      const [pubX, pubY] = pubKey.split('.')
      let padded = plaintext

      while (padded.length < 384) padded += ' '

      return JSON.stringify(
        RecryptApi.encrypt(
          Buffer.from(padded, 'utf-8'), // TODO: Explicit encoding?
          {
            x: Buffer.from(pubX, encoding),
            y: Buffer.from(pubY, encoding)
          },
          Buffer.from(signKeyPair.privKey, encoding)
        )
      ) as string
    },

    async signKeyGen() {
      const signingKeys = RecryptApi.generateEd25519KeyPair()

      return {
        privKey: signingKeys.privateKey.toString(encoding) as string,
        pubKey: signingKeys.publicKey.toString(encoding) as string
      }
    },

    async cryptTransform(transformKey: string, ciphertext: string, signKeyPair: KeyPair) {
      return JSON.stringify(
        RecryptApi.transform(
          JSON.parse(ciphertext),
          JSON.parse(transformKey),
          Buffer.from(signKeyPair.privKey, encoding)
        )
      ) as string
    },

    async decrypt(keyPair: KeyPair, ciphertext: string) {
      return RecryptApi.decrypt(JSON.parse(ciphertext), Buffer.from(keyPair.privKey, encoding))
        .toString('utf-8')
        .trim() as string
    },

    async sign(keyPair: KeyPair, text: string) {
      return RecryptApi.ed25519Sign(
        Buffer.from(keyPair.privKey, encoding),
        Buffer.from(text)
      ).toString(encoding) as string
    },

    async verify(pubKey: string, signature: string, text: string) {
      return RecryptApi.ed25519Verify(
        Buffer.from(pubKey, encoding),
        Buffer.from(text),
        Buffer.from(signature, encoding)
      ) as boolean
    }
  }
}
