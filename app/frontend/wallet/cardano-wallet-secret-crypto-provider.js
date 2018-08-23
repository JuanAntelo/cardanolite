const cbor = require('cbor')
const CardanoCrypto = require('cardano-crypto.js')

const pbkdf2 = require('./helpers/pbkdf2')
const {TxWitness, SignedTransactionStructured} = require('./transaction')
const HdNode = require('./hd-node')
const {parseTxAux} = require('./helpers/cbor-parsers')
const NamedError = require('../helpers/NamedError')
const {packAddress, unpackAddress} = require('./address')
const {NETWORKS} = require('./constants')

const CardanoWalletSecretCryptoProvider = (params, walletState, disableCaching = false) => {
  const state = Object.assign(walletState, {
    masterHdNode: HdNode({secret: params.walletSecret}),
    derivedHdNodes: {},
    derivedXpubs: {},
    derivedAddresses: {},
    network: params.network,
    derivationScheme: params.derivationScheme,
  })

  async function deriveAddresses(derivationPaths, derivationMode) {
    return await Promise.all(
      derivationPaths.map(
        async (derivationPath) => await deriveAddress(derivationPath, derivationMode)
      )
    )
  }

  async function deriveAddress(derivationPath, derivationMode) {
    // in derivation scheme 1, the middle part of the derivation path is skipped
    const actualDerivationPath = toActualDerivationPath(derivationPath)

    const memoKey = JSON.stringify(derivationPath)

    if (!state.derivedAddresses[memoKey]) {
      const xpub = deriveXpub(actualDerivationPath, derivationMode)
      const hdPassphrase = await getRootHdPassphrase()
      state.derivedAddresses[memoKey] = packAddress(
        actualDerivationPath,
        xpub,
        hdPassphrase,
        state.derivationScheme
      )
    }

    return state.derivedAddresses[memoKey]
  }

  function toActualDerivationPath(derivationPath) {
    // in derivation scheme 1 (daedalus) the address derivation ignores the "internal/external" part
    if (state.derivationScheme.type === 'v1' && derivationPath.length === 3) {
      return [derivationPath[0], derivationPath[2]]
    }

    return derivationPath
  }

  async function getWalletId() {
    return await deriveAddress([], 'hardened')
  }

  function getWalletSecret() {
    return state.masterHdNode.toBuffer()
  }

  async function getRootHdPassphrase() {
    return await pbkdf2(state.masterHdNode.extendedPublicKey, 'address-hashing', 500, 32, 'sha512')
  }

  function deriveXpub(derivationPath, derivationMode) {
    const memoKey = JSON.stringify(derivationPath)

    if (disableCaching || !state.derivedXpubs[memoKey]) {
      if (derivationMode === 'hardened') {
        state.derivedXpubs[memoKey] = deriveXpubHardened(derivationPath)
      } else if (derivationMode === 'nonhardened') {
        state.derivedXpubs[memoKey] = deriveXpubNonhardened(derivationPath)
      } else {
        throw Error(`Unknown derivation mode: ${derivationMode}`)
      }
    }

    return state.derivedXpubs[memoKey]
  }

  function deriveXpubHardened(derivationPath) {
    return deriveHdNode(derivationPath).extendedPublicKey
  }

  /*
  * derives first n-1 elements of derivation path the hardened way
  * and only the n-th element is derived the nonhardened way
  */
  function deriveXpubNonhardened(derivationPath) {
    const parentPath = derivationPath.slice(0, derivationPath.length - 1)
    const childPath = derivationPath.slice(derivationPath.length - 1, derivationPath.length)

    // this reduce ensures that this would work even for empty derivation path
    return childPath.reduce(
      (parentXpub, childIndex) =>
        CardanoCrypto.derivePublic(parentXpub, childIndex, state.derivationScheme.number),
      deriveXpub(parentPath, 'hardened')
    )
  }

  function deriveHdNode(derivationPath) {
    const memoKey = JSON.stringify(derivationPath)
    if (disableCaching || !state.derivedHdNodes[memoKey]) {
      state.derivedHdNodes[memoKey] = derivationPath.reduce(deriveChildHdNode, state.masterHdNode)
    }

    return state.derivedHdNodes[memoKey]
  }

  function deriveChildHdNode(hdNode, childIndex) {
    const result = CardanoCrypto.derivePrivate(
      hdNode.toBuffer(),
      childIndex,
      state.derivationScheme.number
    )

    return HdNode({
      secretKey: result.slice(0, 64),
      publicKey: result.slice(64, 96),
      chainCode: result.slice(96, 128),
    })
  }

  async function sign(message, keyDerivationPath) {
    const hdNode = await deriveHdNode(keyDerivationPath)
    const messageToSign = Buffer.from(message, 'hex')

    return CardanoCrypto.sign(messageToSign, hdNode.toBuffer())
  }

  function checkTxInputsIntegrity(txInputs, rawInputTxs) {
    const inputTxs = {}
    for (const rawTx of rawInputTxs) {
      const txHash = CardanoCrypto.blake2b(rawTx, 32).toString('hex')
      inputTxs[txHash] = parseTxAux(rawTx)
    }

    return txInputs
      .map(
        ({txHash, coins, outputIndex}) =>
          inputTxs[txHash] !== undefined && coins === inputTxs[txHash].outputs[outputIndex].coins
      )
      .every((result) => result === true)
  }

  async function signTx(txAux, rawInputTxs) {
    if (!checkTxInputsIntegrity(txAux.inputs, rawInputTxs)) {
      throw NamedError('TransactionRejected')
    }

    const signedTxStructured = await signTxGetStructured(txAux)

    return {
      txHash: signedTxStructured.getId(),
      txBody: cbor.encode(signedTxStructured).toString('hex'),
    }
  }

  async function signTxGetStructured(txAux) {
    const txHash = txAux.getId()

    const witnesses = await Promise.all(
      txAux.inputs.map(async (input) => {
        const derivationPath = await getDerivationPathFromAddress(input.utxo.address)
        const xpub = deriveHdNode(derivationPath).extendedPublicKey
        const protocolMagic = NETWORKS[state.network].protocolMagic

        /*
        * the "01" byte is a constant to denote signatures of transactions
        * the "5820" part is the CBOR prefix for a hex string
        */
        const txSignMessagePrefix = Buffer.concat([
          Buffer.from('01', 'hex'),
          cbor.encode(protocolMagic),
          Buffer.from('5820', 'hex'),
        ]).toString('hex')

        const signature = await sign(`${txSignMessagePrefix}${txHash}`, derivationPath)

        return TxWitness(xpub, signature)
      })
    )

    return SignedTransactionStructured(txAux, witnesses)
  }

  function getDerivationPathFromAddress(address) {
    let derivationPath

    Object.keys(state.derivedAddresses).forEach((key) => {
      if (state.derivedAddresses[key] === address) {
        derivationPath = JSON.parse(key)
      }
    })

    if (derivationPath) {
      return derivationPath
    }

    throw Error(`Unable to do reverse lookup of address ${address}`)
  }

  return {
    deriveAddress,
    deriveAddresses,
    signTx,
    getWalletId,
    getWalletSecret,
    getDerivationPathFromAddress,
    _sign: sign,
    _checkTxInputsIntegrity: checkTxInputsIntegrity,
    _deriveHdNodeFromRoot: deriveHdNode,
    _deriveChildHdNode: deriveChildHdNode,
    _signTxGetStructured: signTxGetStructured,
  }
}

module.exports = CardanoWalletSecretCryptoProvider
