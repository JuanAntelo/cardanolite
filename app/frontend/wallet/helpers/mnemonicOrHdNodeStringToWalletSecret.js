const CardanoCrypto = require('cardano-crypto.js')

const {isMnemonicInPaperWalletFormat, decodePaperWalletMnemonic} = require('../mnemonic')

const mnemonicOrHdNodeStringToWalletSecret = async (mnemonicOrHdNodeString, derivationScheme) => {
  const isMnemonic = mnemonicOrHdNodeString.search(' ') >= 0

  if (isMnemonic) {
    let mnemonic
    if (await isMnemonicInPaperWalletFormat(mnemonicOrHdNodeString)) {
      mnemonic = await decodePaperWalletMnemonic(mnemonicOrHdNodeString)
    } else {
      mnemonic = mnemonicOrHdNodeString
    }
    return CardanoCrypto.walletSecretFromMnemonic(mnemonic, derivationScheme.number)
  } else {
    return Buffer.from(mnemonicOrHdNodeString, 'hex')
  }
}

module.exports = mnemonicOrHdNodeStringToWalletSecret
