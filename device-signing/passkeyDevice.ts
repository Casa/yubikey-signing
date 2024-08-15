import * as bip39 from 'bip39'
import * as bitcoinjs from 'bitcoinjs-lib'
import * as bitcoinMessage from 'bitcoinjs-message'
import * as ecc from '@bitcoin-js/tiny-secp256k1-asmjs'
import * as ethers from 'ethers'
import { Wallet } from 'ethers'

import {
  AuthenticationResponseJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types'
import BIP32Factory from 'bip32'

import { base64ToUtf8, utf8ToBase64 } from '@casa/common/src/lib/encodingUtils'

import COIN, { CoinType, ETH_COIN_TYPES } from './types/coin'
import { extractSignaturesFromPsbt } from './utils/psbtUtils'
import GnosisSafe from './gnosisSafe'
import { PASSKEY_DEVICES } from './types/deviceTypes'
import { readLargeBlob, writeLargeBlob } from './utils/passkeyUtils'
import { ToSign } from './types/toSign'
import { adjustSignatureForPrefix } from './utils/misc'

interface PasskeyDeviceXpubResponse {
  xpub: string
  authenticationResponse: AuthenticationResponseJSON
  blobVersion: PasskeyBlobVersion
}

export enum PasskeyBlobVersion {
  V1 = 'V1',
}

const SEED_VERSION_DELIMITER = '.'
const BLOB_VERSION_CURRENT = PasskeyBlobVersion.V1

interface SignTransactionParams {
  device: PASSKEY_DEVICES
  coin: CoinType
  authenticationOptions: PublicKeyCredentialRequestOptionsJSON
  psbt?: string // BTC only, verify in BTC transaction
  safeAddress?: string // ETH only, address of the Gnosis Safe
  keyPathAddress?: number // ETH only, address index
  toSign: ToSign
  keyPathPurpose: number
  keyPathPurposeIsHardened: boolean
  keyPathCoinType: number
  keyPathAccount: number
  serverHost: string
  token: string
}

const bip32 = BIP32Factory(ecc)

/**
 * Generates a random seed phrase, writes it to the device, and returns the xpub
 * according to the given parameters.  Writing to a passkey largeBlob is done in
 * an authentication ceremony, so a passkey must first be created, stored, then
 * used to generate authenticationOptions
 * prior to calling this function.
 *
 * @param device, hardenedKeyPathPurpose information about how to
 * derive the xpub from a seed phrase
 *
 * @param authenticationOptions, credentialId information about storing
 * the seed phrase, from calls to POST /passkey, then POST /passkey/getCreateOptions
 *
 * Analogous to `exportXpub` in `/packages/device-signing/src/signingDevice.ts`
 *
 * @warning If this function changes the method of seed phrase generation or encoding,
 * increment the version number and document the change in the `encodeSeedPhrase` function
 * so that clients can handle the change.
 */
export async function exportXpub(params: {
  device?: PASSKEY_DEVICES
  hardenedKeyPathPurpose?: number | null
  authenticationOptions: PublicKeyCredentialRequestOptionsJSON
  credentialId: string
}): Promise<PasskeyDeviceXpubResponse> {
  /**
   * This function generates a mnemonic (seed phrase) based on the BIP39 standard. This function does
   * not require an external entropy source because it internally uses a cryptographically secure random
   * number generator (CSPRNG) provided by the environment it runs in.
   *
   * For browsers, the Web Cryptography API (window.crypto.getRandomValues) also provides a CSPRNG.
   * Since generateMnemonic() relies on the underlying environment's RNG, there shouldn't be an issue with
   * predictability unless the environment itself has been compromised or lacks proper seeding mechanisms.
   *
   * @see /tests/mnemonicGeneration.test.ts for a test that generates mnemonics and checks for word
   * frequency distribution with a chi-squared test.
   */
  const seedPhrase = bip39.generateMnemonic()

  // Version encode the seed phrase
  const blob = encodeSeedPhrase({
    seedPhrase,
    blobVersion: BLOB_VERSION_CURRENT,
  })

  // save to largeblob with passkey
  const { authenticationResponse } = await writeLargeBlob({
    options: params.authenticationOptions,
    credentialId: params.credentialId,
    blob,
  })

  const seed = bip39.mnemonicToSeedSync(seedPhrase)
  const node = bip32.fromSeed(seed)

  // Without a key path purpose, use the original xpub
  if (!params.hardenedKeyPathPurpose) {
    return {
      xpub: node.neutered().toBase58(),
      authenticationResponse,
      blobVersion: BLOB_VERSION_CURRENT,
    }
  }

  /**
   * With a key path purpose, derive a new xpub from the hardened key path from the first node,
   * The apostrophe at the end is critical to indicate a hardened key path
   */
  const derivedNode = node.derivePath(`m/${params.hardenedKeyPathPurpose}'`)
  const xpub = derivedNode.neutered().toBase58()

  return {
    xpub,
    authenticationResponse,
    blobVersion: BLOB_VERSION_CURRENT,
  }
}

/**
 * Given a string, and authenticationOptions, returns a signed message
 * using the seed phrase stored on the passkey device.
 *
 * @param message a message to sign, such as a UUID from a Signature row
 * from the database
 *
 * @param authenticationOptions, information about allowed authenticators
 * and transport types to access the passkey-held seed phrase, generated
 * with a call to POST /passkey/getSignOptions
 *
 * Analogous to `getSignedMessage` in `/packages/device-signing/src/signingDevice.ts`
 */
export async function getSignedMessage({
  coin,
  keyPathPurpose,
  keyPathPurposeIsHardened,
  keyPathCoinType,
  keyPathAccount,
  message,
  authenticationOptions,
}: {
  coin: CoinType
  device?: PASSKEY_DEVICES
  keyPathPurpose: number
  keyPathPurposeIsHardened?: boolean
  keyPathCoinType: number
  keyPathAccount: number
  message: string
  authenticationOptions: PublicKeyCredentialRequestOptionsJSON
}): Promise<string> {
  const isEth = ETH_COIN_TYPES.includes(coin)

  const encodedBlob = await readLargeBlob({
    options: authenticationOptions,
  })

  const { seedPhrase } = decodeSeedPhrase(encodedBlob)

  if (isEth) {
    const signer = ethSignerFromSeedAndPath(
      seedPhrase,
      keyPathPurpose,
      keyPathPurposeIsHardened === true,
      keyPathCoinType,
      keyPathAccount,
      0,
    )
    const preadjustedSig = await signer.signMessage(message)
    return preadjustedSig.replace('0x', '')
  }

  const purpose = keyPathPurposeIsHardened
    ? `${keyPathPurpose}'`
    : keyPathPurpose
  const change = '0'
  const address = '0'
  const path = `m/${purpose}/${keyPathCoinType}/${keyPathAccount}/${change}/${address}`
  const seed = bip39.mnemonicToSeedSync(seedPhrase)
  const masterNode = bip32.fromSeed(seed)
  const derivedNode = masterNode.derivePath(path)

  return bitcoinMessage
    .sign(message, derivedNode.privateKey!)
    .toString('base64')
}

/**
 * Given transaction data, and authenticationOptions, returns a signed transaction
 * for ETH or BTC using the seed phrase stored on the passkey device.
 *
 * @param device, coin, information about the transaction that needs to be signed
 *
 * @param authenticationOptions, information about allowed authenticators
 * and transport types to access the passkey-held seed phrase, generated
 * with a call to POST /passkey/getSignOptions
 *
 * Analogous to `signTransaction` in `/packages/device-signing/src/signingDevice.ts`
 */
export async function signTransaction(
  params: SignTransactionParams,
): Promise<string | string[]> {
  switch (params.coin.toUpperCase()) {
    case COIN.btc:
    case COIN.tbtc:
      return await getSignedBitcoinTransaction(params)
    case COIN.ethC:
    case COIN.tethC:
    case COIN.eth:
    case COIN.teth:
      return await getGnosisSafeSignature(params)
  }
  throw new Error()
}

/**
 * Used to load a seed phrase directly from a largeBlob authentication ceremony,
 * without needing to sign a message or transaction. Useful for seed phrase exports
 * or device backups.
 *
 * @param authenticationOptions, information about the intended authenticator, retrieved
 * by calling POST /passkey/getAuthenticatorOptions with a specific credentialId
 *
 * @returns a string, the seed phrase stored on the passkey device
 */
export async function getStoredSeed(params: {
  authenticationOptions: PublicKeyCredentialRequestOptionsJSON
}): Promise<string | null> {
  const encodedBlob = await readLargeBlob({
    options: params.authenticationOptions,
  })

  const { seedPhrase } = decodeSeedPhrase(encodedBlob)
  return seedPhrase
}

/**
 * Given a psbt and authenticationOptions, returns a signature from a
 * passkey-held seed phrase.
 *
 * Analogous to `getSignedBitcoinTransaction` in `/packages/device-signing/src/signingDevice.ts`
 */
async function getSignedBitcoinTransaction(params: {
  authenticationOptions: PublicKeyCredentialRequestOptionsJSON
  psbt?: string
}): Promise<string | string[]> {
  if (!params.psbt) throw new Error('psbt not found')

  const psbt = bitcoinjs.Psbt.fromHex(params.psbt)

  // this is console logged so the user may verify the psbt from js console prior to signing
  // eslint-disable-next-line no-console
  console.warn(`CASA DEVICE-SIGNING LIB\nPreparing to sign PSBT.\n
    Copy and paste this into a 3rd party tool such as https://chainquery.com/bitcoin-cli/decodepsbt to verify hex encoded psbt:\n
    ${psbt?.toBase64()}`)

  const encodedBlob = await readLargeBlob({
    options: params.authenticationOptions,
  })

  const { seedPhrase } = decodeSeedPhrase(encodedBlob)

  const seed = bip39.mnemonicToSeedSync(seedPhrase)
  const hdRoot = bip32.fromSeed(seed)
  const signedPsbt = psbt.signAllInputsHD(hdRoot)

  return extractSignaturesFromPsbt(signedPsbt)
}

/**
 * Given ETH Transaction params and authenticationOptions, returns a signature from a
 * passkey-held seed phrase.
 */
async function getGnosisSafeSignature({
  toSign,
  coin,
  safeAddress,
  keyPathPurpose,
  keyPathPurposeIsHardened,
  keyPathCoinType,
  keyPathAccount,
  keyPathAddress,
  serverHost,
  token,
  authenticationOptions,
}: SignTransactionParams): Promise<string> {
  if (safeAddress == null) {
    throw new Error('Safe address required for Gnosis signature')
  }

  const encodedSeedPhrase = await readLargeBlob({
    options: authenticationOptions,
  })

  const { seedPhrase } = decodeSeedPhrase(encodedSeedPhrase)

  const isTestnet = coin === COIN.teth || coin === COIN.tethC

  const safe = new GnosisSafe(safeAddress, isTestnet, serverHost, token)

  const hash = await safe.getTransactionHash(toSign, coin)

  const signer = ethSignerFromSeedAndPath(
    seedPhrase,
    keyPathPurpose,
    keyPathPurposeIsHardened,
    keyPathCoinType,
    keyPathAccount,
    keyPathAddress!,
  )

  const preadjustedSig = await signer.signMessage(
    Buffer.from(hash.slice(2), 'hex'),
  )
  return adjustSignatureForPrefix(hash.slice(2), preadjustedSig, signer.address)
}

/**
 * get an eth signer object built from the seedphrase and the path vars
 *
 * @param seedPhrase
 * @param keyPathPurpose
 * @param keyPathPurposeIsHardened
 * @param keyPathCoinType
 * @param keyPathAccount
 * @param keyPathAddress
 */
function ethSignerFromSeedAndPath(
  seedPhrase: string,
  keyPathPurpose: number,
  keyPathPurposeIsHardened: boolean,
  keyPathCoinType: number,
  keyPathAccount: number,
  keyPathAddress: number,
): Wallet {
  const seed = bip39.mnemonicToSeedSync(seedPhrase)
  const hdRoot = bip32.fromSeed(seed)
  const purpose = `${keyPathPurpose}${keyPathPurposeIsHardened ? "'" : ''}`
  // change is always 0 for eth
  let derivationPath = `m/${purpose}/${keyPathCoinType}/${keyPathAccount}/0`

  if (keyPathAddress != null) {
    derivationPath += `/${keyPathAddress}`
  }

  const node = hdRoot.derivePath(derivationPath)

  return new ethers.ethers.Wallet(node.privateKey!)
}

function isValidSeedPhrase(seedPhrase: string): boolean {
  return bip39.validateMnemonic(seedPhrase)
}

export function encodeSeedPhrase({
  seedPhrase,
  blobVersion = BLOB_VERSION_CURRENT,
}: {
  seedPhrase: string
  blobVersion?: PasskeyBlobVersion
}): string {
  const isValid = isValidSeedPhrase(seedPhrase)

  if (!isValid) {
    throw new Error('Invalid seed phrase')
  }

  switch (blobVersion) {
    case PasskeyBlobVersion.V1:
      const base64Seed = utf8ToBase64(seedPhrase)
      return `${base64Seed}${SEED_VERSION_DELIMITER}${blobVersion}`
    default:
      throw new Error('Unsupported seed phrase version')
  }
}

export function decodeSeedPhrase(encodedSeedPhrase: string): {
  seedPhrase: string
  version?: PasskeyBlobVersion
} {
  if (isValidSeedPhrase(encodedSeedPhrase)) {
    console.warn(
      `Seed phrase is not version encoded. This device may not be able to be tracked
      for updates to security vulnerabilities around generation schema.
      `,
    )

    return { seedPhrase: encodedSeedPhrase }
  }

  const [base64Seed, version] = encodedSeedPhrase.split(SEED_VERSION_DELIMITER)

  if (version !== PasskeyBlobVersion.V1) {
    throw new Error('Unsupported seed phrase version')
  }

  const seedPhrase = base64ToUtf8(base64Seed)

  return { seedPhrase, version }
}
