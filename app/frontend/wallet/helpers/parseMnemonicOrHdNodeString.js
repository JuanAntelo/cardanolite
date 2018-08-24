const {decodePaperWalletMnemonic, walletSecretFromMnemonic} = require('cardano-crypto.js')

const {isMnemonicInPaperWalletFormat} = require('../mnemonic')
const {DERIVATION_SCHEMES} = require('../constants')

const determineDerivationSchemeFromMnemonic = (mnemonic) => {
  return mnemonic.split(' ').length === 12 ? DERIVATION_SCHEMES.v1 : DERIVATION_SCHEMES.v2
}

const parseMnemonicOrHdNodeString = async (mnemonicOrHdNodeString) => {
  let walletSecret
  let derivationScheme = DERIVATION_SCHEMES.v1

  const isMnemonic = mnemonicOrHdNodeString.search(' ') >= 0

  if (isMnemonic) {
    let mnemonic
    if (await isMnemonicInPaperWalletFormat(mnemonicOrHdNodeString)) {
      mnemonic = await decodePaperWalletMnemonic(mnemonicOrHdNodeString)
    } else {
      mnemonic = mnemonicOrHdNodeString
    }

    derivationScheme = determineDerivationSchemeFromMnemonic(mnemonic)
    walletSecret = await walletSecretFromMnemonic(mnemonic, derivationScheme.number)
  } else {
    walletSecret = Buffer.from(mnemonicOrHdNodeString, 'hex')
  }

  return {
    walletSecret,
    derivationScheme,
  }
}

module.exports = parseMnemonicOrHdNodeString
