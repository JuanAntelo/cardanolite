describe('CardanoLite Test Suite', () => {
  describe('Mnemonic Handling', () => {
    require('./mnemonic')
  })
  describe('CBOR', () => {
    require('./cbor')
  })
  describe('Mnemonic Crypto Provider', () => {
    require('./cardano-wallet-secret-crypto-provider')
  })
  describe('Blockchain Explorer', () => {
    require('./blockchain-explorer')
  })
  describe('Cardano Wallet', () => {
    require('./cardano-wallet')
  })
  describe('Import/Export Wallet as JSON', () => {
    require('./keypass-json')
  })
})
