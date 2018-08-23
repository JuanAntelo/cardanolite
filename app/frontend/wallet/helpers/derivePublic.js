const CardanoCrypto = require('cardano-crypto.js')

const derivePublic = (xpub, childIndex, derivationScheme) =>
  CardanoCrypto.derivePublic(xpub, childIndex, derivationScheme)

module.exports = derivePublic
