const assert = require('assert')
const CardanoCrypto = require('cardano-crypto.js')
const cbor = require('cbor')
const {
  blake2b,
  sha3_256, // eslint-disable-line camelcase
  crc32,
  base58,
} = require('cardano-crypto.js')

const {generateMnemonic, decodePaperWalletMnemonic} = require('../../frontend/wallet/mnemonic')

const paperWalletMnemonic =
  'force usage medal chapter start myself odor ripple concert aspect wink melt afford lounge smart bulk way hazard burden type broken defense city announce reward same tumble'
const standardMnemonic = 'swim average antenna there trap nice good stereo lion safe next brief'

describe('mnemonic generation', () => {
  const mnemonicString = generateMnemonic()

  it('should produce 12 words', () => {
    assert.equal(mnemonicString.split(' ').length, 12)
  })
})

// eslint-disable-next-line prefer-arrow-callback
describe('paper wallet decoding', function() {
  this.timeout(10000)
  it('should properly decode paper wallet mnemonic', async () => {
    assert.equal(await decodePaperWalletMnemonic(paperWalletMnemonic), standardMnemonic)
  })
})

// eslint-disable-next-line prefer-arrow-callback
describe('aaaaa', function() {
  it('aaaaaa', async () => {
    const mnemonic =
      'cost dash dress stove morning robust group affair stomach vacant route volume yellow salute laugh'
    const walletSecret = CardanoCrypto.walletSecretFromMnemonic(mnemonic, 2)

    console.log(walletSecret.toString('hex'))

    const accountSecret = CardanoCrypto.derivePrivate(walletSecret, 0x80000000, 2)

    console.log(accountSecret.toString('hex'))

    const derivedSecret1 = CardanoCrypto.derivePrivate(accountSecret, 0, 2)
    const derivedSecret2 = CardanoCrypto.derivePrivate(derivedSecret1, 0, 2)

    console.log(derivedSecret2.toString('hex'))
    const xpub = derivedSecret2.slice(64, 128)

    const addrRoot = [0, [0, xpub], new Map()]

    const firstHash = sha3_256(cbor.encode(addrRoot))
    const hash = blake2b(firstHash, 28)

    const addrDataEncoded = cbor.encode([hash, new Map(), 0])

    console.log(
      base58.encode(cbor.encode([new cbor.Tagged(24, addrDataEncoded), crc32(addrDataEncoded)]))
    )

    console.log(hash.toString('hex'))

    // internal xpub hash
    console.log('36EC0642C82D49983F6E61423D0021205580C38722B733EB6F45F5E0')

    // external xpub hash
    console.log('605E4B0992E1AA56CC05CC54F4AF3BFD262CBA450AC4D640AE63FFF7')
  })
})
