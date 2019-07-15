import recryptApiToNaturalRights from '../src/natural-rights-recrypt'

const Recrypt = require('@ironcorelabs/recrypt-node-binding')
const RecryptApi = new Recrypt.Api256()
const Primitives = recryptApiToNaturalRights(RecryptApi)

describe('natural rights primitives', () => {
  it('allows encryption and decryption', async () => {
    const cryptKeyPair = await Primitives.cryptKeyGen()
    const signKeyPair = await Primitives.signKeyGen()
    const plaintext = 'Some plaintext'
    const ciphertext = await Primitives.encrypt(cryptKeyPair.pubKey, plaintext, signKeyPair)
    const decrypted = await Primitives.decrypt(cryptKeyPair, ciphertext)
    expect(decrypted).toEqual(plaintext)
  })

  it('allows re-encryption and decryption', async () => {
    const cryptKeyPair = await Primitives.cryptKeyGen()
    const otherCryptKeyPair = await Primitives.cryptKeyGen()
    const signKeyPair = await Primitives.signKeyGen()
    const plaintext = 'Some plaintext'
    const ciphertext = await Primitives.encrypt(cryptKeyPair.pubKey, plaintext, signKeyPair)
    const transformKey = await Primitives.cryptTransformKeyGen(
      cryptKeyPair,
      otherCryptKeyPair.pubKey,
      signKeyPair
    )
    const transformed = await Primitives.cryptTransform(transformKey, ciphertext, signKeyPair)
    const decrypted = await Primitives.decrypt(otherCryptKeyPair, transformed)
    expect(decrypted).toEqual(plaintext)
  })

  it('supports signatures', async () => {
    const signKeyPair = await Primitives.signKeyGen()
    const otherSignKeyPair = await Primitives.signKeyGen()
    const text = 'Some text to sign'
    const signature = await Primitives.sign(signKeyPair, text)
    expect(await Primitives.verify(signKeyPair.pubKey, signature, text)).toEqual(true)
    expect(await Primitives.verify(otherSignKeyPair.pubKey, signature, text)).toEqual(false)
  })
})
