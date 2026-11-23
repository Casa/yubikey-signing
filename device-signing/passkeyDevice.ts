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

import { base64ToUtf8, utf8ToBase64 } from 'casa-common/src/utils/encodingUtils'

import COIN, { CoinType, ETH_COIN_TYPES } from './types/coin'
import { extractSignaturesFromPsbt } from './utils/psbtUtils'
import GnosisSafe from './gnosisSafe'
import { PASSKEY_DEVICES } from './types/deviceTypes'
import { readLargeBlob, writeLargeBlob } from './utils/passkeyUtils'
import { ToSign } from './types/toSign'
import { adjustSignatureForPrefix } from './utils/misc'
import { wipeBytes } from './utils/memory'

interface PasskeyDeviceXpubResponse {
  xpub: string
  authenticationResponse: AuthenticationResponseJSON
  blobVersion: PasskeyBlobVersion
}

export enum PasskeyBlobVersion {
  V1 = 'V1',
  V2 = 'V2',
}

// Historic V1 blobs were emitted with `.` as the delimiter. V2 uses `::` per
// spec. The decoder accepts either to preserve backward compatibility with
// V1 keys already in the field; new writes pick the delimiter per version.
const V1_DELIMITER = '.'
const V2_DELIMITER = '::'
const BLOB_VERSION_CURRENT = PasskeyBlobVersion.V1
const MAX_BLOB_SIZE_BYTES = 900
const MAX_PASSPHRASE_LENGTH = 128
const MIN_MNEMONIC_WORDS = 12

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
  seedPhrase?: string
  passphrase?: string
}): Promise<PasskeyDeviceXpubResponse> {
  /**
   * Generates a BIP-39 mnemonic (seed phrase). No external entropy source is
   * needed: `generateMnemonic` takes 128 bits from `@noble/hashes`
   * `randomBytes`, which calls the environment's WebCrypto CSPRNG
   * (`crypto.getRandomValues`). In the browser that is the Web Cryptography
   * API. If no WebCrypto implementation exists, `randomBytes` throws instead of
   * substituting a weaker RNG, so this call fails rather than returning a
   * predictable phrase.
   *
   * The strength of a real seed therefore rests on the browser CSPRNG. Unit
   * tests cannot measure that: they only exercise Node's RNG under the test
   * runner. `/tests/mnemonicGeneration.test.ts` accordingly asserts the parts
   * that are verifiable here — the entropy comes from `crypto.getRandomValues`,
   * all 128 bits reach the phrase unchanged, BIP-39 encoding matches the spec
   * vectors, and an RNG failure or absence propagates as an error.
   */
  const seedPhrase = params.seedPhrase ?? bip39.generateMnemonic()

  // Use V2 encoding when a passphrase is provided, otherwise use the current default
  const blobVersion =
    params.passphrase != null ? PasskeyBlobVersion.V2 : BLOB_VERSION_CURRENT

  // Version encode the seed phrase
  const blob = encodeSeedPhrase({
    seedPhrase,
    passphrase: params.passphrase,
    blobVersion,
  })

  // save to largeblob with passkey
  const { authenticationResponse } = await writeLargeBlob({
    options: params.authenticationOptions,
    credentialId: params.credentialId,
    blob,
  })

  // wipe seed bytes after deriving xpub. xpub itself is public
  // and contains no key material, but the binary seed should be zeroed.
  const seed = bip39.mnemonicToSeedSync(seedPhrase, params.passphrase)
  let xpub: string
  try {
    const node = bip32.fromSeed(seed)
    xpub = !params.hardenedKeyPathPurpose
      ? node.neutered().toBase58()
      : node
          .derivePath(`m/${params.hardenedKeyPathPurpose}'`)
          .neutered()
          .toBase58()
  } finally {
    wipeBytes(seed)
  }

  return {
    xpub,
    authenticationResponse,
    blobVersion,
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

  const { seedPhrase, passphrase } = decodeSeedPhrase(encodedBlob)

  if (isEth) {
    const signer = ethSignerFromSeedAndPath(
      seedPhrase,
      keyPathPurpose,
      keyPathPurposeIsHardened === true,
      keyPathCoinType,
      keyPathAccount,
      0,
      passphrase,
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
  // wipe seed bytes after deriving the signing key. See note
  // on deriveXpub above — this trims memory exposure for the binary seed
  // material derived from the user's mnemonic.
  const seed = bip39.mnemonicToSeedSync(seedPhrase, passphrase)
  try {
    const masterNode = bip32.fromSeed(seed)
    const derivedNode = masterNode.derivePath(path)

    return bitcoinMessage
      .sign(message, derivedNode.privateKey!)
      .toString('base64')
  } finally {
    wipeBytes(seed)
  }
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

  const psbt = bitcoinjs.Psbt.fromBase64(params.psbt)

  // this is console logged so the user may verify the psbt from js console prior to signing
  // Do not print the PSBT: it carries the vault topology, UTXO set, and
  // output scripts. The app shows it to the user before approval.
  // eslint-disable-next-line no-console
  console.warn('CASA DEVICE-SIGNING LIB: preparing to sign a PSBT')

  const encodedBlob = await readLargeBlob({
    options: params.authenticationOptions,
  })

  const { seedPhrase, passphrase } = decodeSeedPhrase(encodedBlob)

  // wipe binary seed bytes after signing.
  const seed = bip39.mnemonicToSeedSync(seedPhrase, passphrase)
  try {
    const hdRoot = bip32.fromSeed(seed)
    const signedPsbt = psbt.signAllInputsHD(hdRoot)

    return extractSignaturesFromPsbt(signedPsbt, {
      // PD-627: bind the extracted signature to this device's key origin.
      masterFingerprint: hdRoot.fingerprint.toString('hex'),
    })
  } finally {
    wipeBytes(seed)
  }
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

  const { seedPhrase, passphrase } = decodeSeedPhrase(encodedSeedPhrase)

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
    passphrase,
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
  passphrase?: string,
): Wallet {
  // wipe seed bytes after deriving the leaf private key. The
  // ethers.Wallet captures the leaf privateKey by value; the master seed and
  // intermediate node are no longer needed once we have it.
  const seed = bip39.mnemonicToSeedSync(seedPhrase, passphrase)
  try {
    const hdRoot = bip32.fromSeed(seed)
    const purpose = `${keyPathPurpose}${keyPathPurposeIsHardened ? "'" : ''}`
    // change is always 0 for eth
    let derivationPath = `m/${purpose}/${keyPathCoinType}/${keyPathAccount}/0`

    if (keyPathAddress != null) {
      derivationPath += `/${keyPathAddress}`
    }

    const node = hdRoot.derivePath(derivationPath)

    return new ethers.ethers.Wallet(node.privateKey!)
  } finally {
    wipeBytes(seed)
  }
}

export function isValidSeedPhrase(seedPhrase: string): boolean {
  return bip39.validateMnemonic(seedPhrase)
}

/**
 * Returns the BIP-39 English word list (2048 words).
 * Used client-side for layered seed phrase validation.
 */
export function getBip39WordList(): string[] {
  return bip39.wordlists.english ?? bip39.wordlists.EN
}

/**
 * Derives the xpub from a seed phrase and optional passphrase.
 * Used client-side to validate that a seed phrase matches a device's recorded xpub
 * before importing it onto a YubiKey.
 *
 * Casa stores `device.xpub` at depth 1 — `m/{hardenedKeyPathPurpose}'`.
 * (Verified by decoding stored xpubs: the depth byte is 1 and the only
 * derivation step is the hardened purpose. The deeper key xpubs in the `keys`
 * table at `m/purpose'/coinType/account` are derived FROM device.xpub, not
 * generated independently from the seed.)
 */
export function deriveXpub(
  seedPhrase: string,
  passphrase?: string,
  hardenedKeyPathPurpose?: number | null,
): string {
  // hold the binary seed in a Uint8Array and overwrite it
  // before drop. JS strings (seedPhrase, passphrase) cannot be wiped, but
  // the derived bytes can be. This trims the window during which the
  // mnemonic-derived material lives in process memory.
  const seed = bip39.mnemonicToSeedSync(seedPhrase, passphrase)
  try {
    const node = bip32.fromSeed(seed)
    if (!hardenedKeyPathPurpose) {
      return node.neutered().toBase58()
    }
    return node.derivePath(`m/${hardenedKeyPathPurpose}'`).neutered().toBase58()
  } finally {
    wipeBytes(seed)
  }
}

/**
 * BIP-39 normalization applied at both encode and decode time so the stored
 * mnemonic is canonical regardless of how the user typed it.
 *
 * Passphrases are stored verbatim — bip39 applies NFKD at derivation time per
 * the BIP-39 spec, and pre-normalizing would diverge from how Ledger / Trezor
 * handle passphrases.
 */
export function normalizeMnemonic(input: string): string {
  return input.trim().toLowerCase().split(/\s+/).join(' ')
}

export function encodeSeedPhrase({
  seedPhrase,
  passphrase,
  blobVersion = BLOB_VERSION_CURRENT,
}: {
  seedPhrase: string
  passphrase?: string
  blobVersion?: PasskeyBlobVersion
}): string {
  const normalized = normalizeMnemonic(seedPhrase)

  if (!isValidSeedPhrase(normalized)) {
    throw new Error('Invalid seed phrase')
  }

  if (passphrase != null && passphrase.length > MAX_PASSPHRASE_LENGTH) {
    throw new Error(
      `Passphrase must be ${MAX_PASSPHRASE_LENGTH} characters or fewer`,
    )
  }

  let blob: string
  switch (blobVersion) {
    case PasskeyBlobVersion.V1: {
      const base64Seed = utf8ToBase64(normalized)
      blob = `${base64Seed}${V1_DELIMITER}${blobVersion}`
      break
    }
    case PasskeyBlobVersion.V2: {
      // Only include `passphrase` when defined and non-empty so the encoded
      // payload has the smallest possible footprint and round-trips cleanly.
      const payloadObj: { seedPhrase: string; passphrase?: string } = {
        seedPhrase: normalized,
      }
      if (passphrase != null && passphrase !== '') {
        payloadObj.passphrase = passphrase
      }
      const base64Payload = utf8ToBase64(JSON.stringify(payloadObj))
      blob = `${base64Payload}${V2_DELIMITER}${blobVersion}`
      break
    }
    default:
      throw new Error('Unsupported seed phrase version')
  }

  if (blob.length > MAX_BLOB_SIZE_BYTES) {
    throw new Error('Encoded blob exceeds largeBlob size limit')
  }

  return blob
}

export function decodeSeedPhrase(encodedSeedPhrase: string): {
  seedPhrase: string
  passphrase?: string
  version: PasskeyBlobVersion
} {
  if (typeof encodedSeedPhrase !== 'string' || encodedSeedPhrase === '') {
    throw new Error('Invalid blob format: empty payload')
  }

  // Try V2 (`::` delimiter) first, then fall back to V1 (`.`). Order matters:
  // V2's delimiter contains the V1 delimiter, so checking V2 first prevents
  // mis-parsing a `::V2` blob as a `.V2` blob with an extra leading colon.
  const v2Match = encodedSeedPhrase.match(/^(.+)::(V1|V2)$/)
  const v1Match = encodedSeedPhrase.match(/^(.+)\.(V1|V2)$/)
  const match = v2Match ?? v1Match

  if (!match) {
    // Compat: blobs written before the V1/V2 versioning scheme (pre-CENG-3323,
    // 2024-07) are stored as a raw BIP-39 mnemonic. Preserve signing access
    // for those legacy devices; reject anything that isn't a valid mnemonic.
    const candidate = normalizeMnemonic(encodedSeedPhrase)
    if (isValidSeedPhrase(candidate)) {
      return { seedPhrase: candidate, version: PasskeyBlobVersion.V1 }
    }
    throw new Error(
      'Invalid blob format: missing or unrecognized version suffix',
    )
  }

  const [, base64Data, versionTag] = match
  const version = versionTag as PasskeyBlobVersion

  if (version === PasskeyBlobVersion.V1) {
    const seedPhrase = normalizeMnemonic(base64ToUtf8(base64Data))
    // PD-2462: a word count alone accepts a corrupted or substituted blob and
    // silently derives a wrong key. Enforce the same BIP-39 checksum and
    // wordlist validation that encodeSeedPhrase applies so decode fails closed.
    if (
      seedPhrase === '' ||
      seedPhrase.split(' ').length < MIN_MNEMONIC_WORDS ||
      !isValidSeedPhrase(seedPhrase)
    ) {
      throw new Error('Invalid V1 blob: decoded seed phrase is malformed')
    }
    return { seedPhrase, version }
  }

  if (version === PasskeyBlobVersion.V2) {
    let parsed: unknown
    try {
      parsed = JSON.parse(base64ToUtf8(base64Data))
    } catch {
      throw new Error('Invalid V2 blob: base64 payload is not valid JSON')
    }

    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      !('seedPhrase' in parsed)
    ) {
      throw new Error('Invalid V2 blob: missing required seedPhrase field')
    }

    const { seedPhrase: rawSeed, passphrase } = parsed as {
      seedPhrase: unknown
      passphrase?: unknown
    }

    if (typeof rawSeed !== 'string') {
      throw new Error('Invalid V2 blob: seedPhrase must be a string')
    }

    const seedPhrase = normalizeMnemonic(rawSeed)
    // PD-2462: validate the BIP-39 checksum and wordlist, not only the word
    // count, so a corrupted or substituted blob fails instead of deriving a
    // wrong key.
    if (
      seedPhrase.split(' ').length < MIN_MNEMONIC_WORDS ||
      !isValidSeedPhrase(seedPhrase)
    ) {
      throw new Error('Invalid V2 blob: seedPhrase is malformed')
    }

    if (passphrase != null && typeof passphrase !== 'string') {
      throw new Error('Invalid V2 blob: passphrase must be a string if present')
    }

    return {
      seedPhrase,
      passphrase:
        passphrase != null && passphrase !== ''
          ? (passphrase as string)
          : undefined,
      version,
    }
  }

  throw new Error('Unsupported seed phrase version')
}
