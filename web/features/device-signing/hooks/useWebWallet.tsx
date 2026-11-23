import * as passkeyDevice from '@casa/device-signing/src/passkeyDevice'
import { getStoredSeed } from '@casa/device-signing/src/passkeyDevice'
import * as passkeyPrfDevice from '@casa/device-signing/src/passkeyPrfDevice'
import {
  getSeedPhraseForRecovery,
  type AuthenticatorAttachmentResult,
} from '@casa/device-signing/src/passkeyPrfDevice'
import { PASSKEY_DEVICES } from '@casa/device-signing/src/types/deviceTypes'
import { ToSign } from '@casa/device-signing/src/types/toSign'
import * as passkeyUtils from '@casa/device-signing/src/utils/passkeyUtils'
import {
  PasskeyError,
  PasskeyErrorCodes,
} from '@casa/device-signing/src/utils/passkeyUtils'
import {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types'
import { AuthenticationResponseJSON } from '@simplewebauthn/types'
import {
  useState,
  createContext,
  ReactElement,
  ReactNode,
  useContext,
  useCallback,
  useEffect,
  useRef,
} from 'react'
import toast from 'react-hot-toast'
import { useParams } from 'react-router-dom'
import { AnyObject } from 'yup/lib/types'

import { tryCatch } from 'casa-common/src/utils/errorUtils'

import { IS_MOBILE_DEVICE } from 'src/constants/browser'
import { BTC_HARDENED_PURPOSE, DEVICE_TYPE, Device } from 'src/constants/device'
import { Key, Signature } from 'src/constants/signature'
import {
  COIN_TYPE,
  ETH_COIN_TYPES,
  WalletAccount,
} from 'src/constants/wallet-accounts'
import { isEthOnlyDeviceGroup } from 'src/features/device-signing/utils/ethDeviceGroup'
import {
  KeyLabels,
  wrongKeyMessage,
} from 'src/features/device-signing/utils/keyNames'
import { parsePasskeyError } from 'src/features/device-signing/utils/parseError'
import { readSupportedProviders } from 'src/features/device-signing/utils/passkeyProviders'
import {
  findPasskeySigningKeyCandidates,
  formatSignTxParams,
  resolvePasskeySigningDeviceId,
  verifySignatureLocationType,
} from 'src/features/device-signing/utils/signatureUtils'
import useApi from 'src/hooks/useApi'
import useTranslate from 'src/hooks/useTranslate'

// Not used for display, stored as default passkey name in the database for future reference
const DEFAULT_WEB_WALLET_NAME = 'YubiKey'

/**
 * An ENUM value indicating the purpose of the passkey. Web wallet passkeys should not
 * enable a user to sign in, as this would allow a single security key to be used for
 * account access AND transaction signing.
 */

/**
 * The inputs required to sign a transaction with a web wallet, analogous to inputs to
 * `DeviceSigning.tsx`, but separated here to handle the complex web wallet process.
 */
export interface TransactionInputs {
  toSign: ToSign | null
  coinType: COIN_TYPE | null
  signature: Signature
  walletAccount: WalletAccount | null
  isTestnet: boolean
}

export interface YubiKeyExportData {
  xpub: string
  authenticationResponse: AuthenticationResponseJSON
  blobVersion: string
  token: string
}

type WebWalletState = {
  // Resolves with the credentialId on success (or null on any error). The
  // explicit return value lets callers chain follow-up work without reading
  // `credentialId` from a stale closure — see ImportPasskeySetup in
  // YubikeyImport.tsx for the failure mode that motivated this.
  createPasskey: () => Promise<string | null>
  // seedPhrase is only provided for yubikey copy/import else its generated securely
  // passphrase is only provided for seed phrase import (BIP-39 passphrase)
  // prfPassphrase is the PRF-device BIP-39 passphrase (device-signing v3
  // derivation: 12 words + passphrase), gated by PIN and wired up by PasskeyRegister.tsx — kept as a
  // distinctly-named param so it can never be confused with the YubiKey
  // seed-import `passphrase` above, which has different semantics.
  createWallet: (
    seedPhrase?: string,
    passphrase?: string,
    prfPassphrase?: string,
  ) => Promise<void>
  writeSeedToYubiKey: (
    seedPhrase: string,
    passphrase?: string,
  ) => Promise<YubiKeyExportData | null>
  // prfPassphrase here is the PRF-device BIP-39 passphrase (device-signing v3
  // derivation: 12 words + passphrase), gated by PIN and wired up by PasskeySign.tsx (Task 10) — not
  // to be conflated with the YubiKey seed-import passphrase above. Required
  // (and validated non-empty) for PRF passkeys; ignored for largeBlob
  // YubiKeys, which don't use a BIP-39 passphrase.
  signHealthCheck: (prfPassphrase?: string) => Promise<void>
  signTransaction: (prfPassphrase?: string) => Promise<void>
  getSeedPhrase: (
    passphrase?: string,
    recoveryDevice?: Pick<Device, 'xpub' | 'hardenedKeyPathPurpose'>,
  ) => Promise<void>
  onConfirmPhrase: () => void
  resetPhrase: () => void
  resetErrors: () => void
  // Lets callers install a fresh continuation token for the next getSeedPhrase
  // call after the handoff token that authenticated the current flow has been
  // revoked server-side (e.g. the single-use export link's exp token — see
  // PasskeyRecovery.tsx's RecoveryPinEntry). getSeedPhrase already prefers
  // `backupToken ?? jwt` internally; this is the only way to set it from
  // outside the provider.
  setBackupToken: (token: string | undefined) => void
  // The token installed by setBackupToken. The export PIN step re-sends it on
  // a same-session retry, because the email link's own token is single use.
  backupToken: string | undefined
  // Providers the server allows for a new passkey signer, from the last
  // getCreateOptions response. Null until that response arrives (or on an
  // older server); callers fall back to the full list.
  supportedProviders: string[] | null
  passkeyError: PasskeyError | null
  walletError: PasskeyError | null
  signError: PasskeyError | null
  phraseError: PasskeyError | null
  passkeyLoading: boolean
  walletLoading: boolean
  deviceUpdateLoading: boolean
  signatureLoading: boolean
  phraseLoading: boolean
  phraseConfirmed: boolean
  signature?: Signature
  // The device whose PRF passkey will sign, resolved via
  // resolvePasskeySigningDeviceId (signature.key for health checks; the
  // wallet account's passkey key for transactions, whose Signature rows have
  // keyId null). null when no single device can be resolved — consumers must
  // fail loudly rather than call device-scoped endpoints with ''.
  passkeySigningDeviceId: string | null
  // All keys whose passkey could sign, for the PIN screen's key chooser when
  // passkeySigningDeviceId is null and more than one candidate exists.
  passkeySigningKeyCandidates: Key[]
  // The signing wallet account's custom key labels, to name the candidates
  signingKeyLabels: KeyLabels
  // Records the user's chooser selection; validated against the candidates.
  selectPasskeySigningDevice: (deviceId: string) => void
  credentialId: string | null
  xPub: string | null
  phrase: string[] | null
  signatureResult: string | null
  // How the passkey answered the last completed health check ('platform' or
  // 'cross-platform' for a QR/hybrid phone hand-off). null before a health
  // check completes, for non-PRF devices, or when the browser does not say.
  healthCheckAuthenticatorAttachment: AuthenticatorAttachmentResult
  isHealthCheck: boolean
  isTransaction: boolean
}

const WebWalletContext = createContext<WebWalletState>({} as WebWalletState)

/**
 * A React context provider that manages the state and logic for the web wallet process. This
 * is divergent from other hardware wallets due to the additional server-based options calls
 * and error states that may occur during the web wallet process.
 *
 * @param device The device object to be used for the web wallet process
 * @param signature The signature object to be used for the web wallet process, if applicable
 * @param isHealthCheck A boolean indicating whether the wrapped component is used in a health check
 * @param isTransaction A boolean indicating whether the wrapped component is used in a transaction
 */
export function WebWalletProvider({
  device,
  deviceType,
  signature,
  jwt,
  transactionInputs,
  isHealthCheck,
  isTransaction,
  children,
}: {
  device?: Device
  deviceType?: DEVICE_TYPE
  signature?: Signature
  jwt: string
  isHealthCheck?: boolean
  isTransaction?: boolean
  transactionInputs?: TransactionInputs
  children: ReactNode
}): ReactElement {
  // Loading states for each step of the web wallet process
  const [passkeyLoading, setPasskeyLoading] = useState(false)
  const [walletLoading, setWalletLoading] = useState(false)
  const [deviceUpdateLoading, setDeviceUpdateLoading] = useState(false)
  const [signatureLoading, setSignatureLoading] = useState(false)
  const [phraseLoading, setPhraseLoading] = useState(false)

  // Error states for each step of the web wallet process
  const [passkeyError, setPasskeyError] = useState<PasskeyError | null>(null)
  const [supportedProviders, setSupportedProviders] = useState<string[] | null>(
    null,
  )
  const [walletError, setWalletError] = useState<PasskeyError | null>(null)
  const [signError, setSignError] = useState<PasskeyError | null>(null)
  const [phraseError, setPhraseError] = useState<PasskeyError | null>(null)

  // Success states for each step of the web wallet process
  const [credentialId, setCredentialId] = useState<string | null>(null)
  const [xPub, setXPub] = useState<string | null>(null)
  // The purpose xPub was exported at. The device prop is fetched before the
  // xpub attach, so its purpose can be stale for the setup backup check.
  const [xPubHardenedKeyPathPurpose, setXPubHardenedKeyPathPurpose] = useState<
    number | null | undefined
  >()
  const [backupToken, setBackupToken] = useState<string | undefined>()
  const [signatureResult, setSignatureResult] = useState<string | null>(null)
  const [
    healthCheckAuthenticatorAttachment,
    setHealthCheckAuthenticatorAttachment,
  ] = useState<AuthenticatorAttachmentResult>(null)
  const [phrase, setPhrase] = useState<string[] | null>(null)
  const [phraseConfirmed, setPhraseConfirmed] = useState<boolean>(false)

  // Url parameters for the web wallet setup process
  const { deviceId } = useParams<{ deviceId: string }>()
  const { translateToString } = useTranslate()

  // Fallback wallet account fetched by the provider itself (see the effect
  // below) when the caller did not supply one with populated keys — e.g. the
  // health-check entry point (DeviceVerifyPage) passes no transactionInputs,
  // and the transaction page's wallet-account fetch may not have landed yet.
  const [fetchedSigningWalletAccount, setFetchedSigningWalletAccount] =
    useState<WalletAccount | null>(null)

  const suppliedWalletAccount = transactionInputs?.walletAccount
  const signingWalletAccount =
    (suppliedWalletAccount?.keys?.length ?? 0) > 0
      ? suppliedWalletAccount
      : fetchedSigningWalletAccount

  // The user's explicit choice when several passkey keys are equally
  // plausible signers (rare: e.g. two members' passkey keys in a shared
  // vault with no designated signer). Set from the PIN screen's key chooser.
  const [selectedSigningDeviceId, setSelectedSigningDeviceId] = useState<
    string | null
  >(null)

  // All wallet-account keys whose passkey could sign this signature. Empty
  // when the signature is already bound to a key (health checks).
  const passkeySigningKeyCandidates: Key[] =
    signature?.key?.deviceId != null
      ? []
      : findPasskeySigningKeyCandidates({
          signature,
          walletAccount: signingWalletAccount,
        })

  // The device whose PRF passkey will sign. Health-check signatures carry it
  // on signature.key; transaction signatures have keyId null, so it is
  // resolved from the wallet account's passkey keys — or, when several are
  // equally plausible, from the user's chooser selection (validated against
  // the current candidates so a stale selection can never leak through).
  // Used by both the PIN passphrase release (PasskeySignPinEntry) and the
  // sign-options scoping in signTransaction so the released passphrase and
  // the prompted credential always belong to the same device.
  const resolvedSigningDeviceId = resolvePasskeySigningDeviceId({
    signature,
    walletAccount: signingWalletAccount,
  })
  const validatedSelection =
    selectedSigningDeviceId != null &&
    passkeySigningKeyCandidates.some(
      (key) => (key.deviceId ?? key.device?.id) === selectedSigningDeviceId,
    )
      ? selectedSigningDeviceId
      : null
  const passkeySigningDeviceId = resolvedSigningDeviceId ?? validatedSelection

  const isPasskeyPrf = deviceType === DEVICE_TYPE.PASSKEY
  const passkeyPurpose = isPasskeyPrf ? 'platform-sign' : 'sign'
  // A passkey signer in a BTC vault always exports at m/45', like Ledger
  // (DeviceExport). An ETH vault keeps its group purpose. ETH uses the same
  // rule as vault-api (supportedNetworks), so the two cannot disagree.
  const firstDeviceGroup = device?.deviceGroups?.[0]
  const isEthDevice =
    firstDeviceGroup != null && isEthOnlyDeviceGroup(firstDeviceGroup)
  const passkeyPrfHardenedKeyPathPurpose = isEthDevice
    ? device?.hardenedKeyPathPurpose
    : BTC_HARDENED_PURPOSE
  const walletName = isPasskeyPrf ? 'Passkey' : DEFAULT_WEB_WALLET_NAME

  // vault-api user id (same value shown at admin-web's /users/:keymasterId) -
  // tagged on every parsePasskeyError log below so support can search Datadog
  // by it. `signature` covers signing/health-check flows; `device` (present
  // during setup/export, before any signature exists) is the fallback.
  const userId = signature?.signingUserId ?? device?.userId

  /**
   * On retry states, reset all errors to allow the user to try again. The lingering
   * success states may indicate where the user left off in the process
   */
  const resetErrors = () => {
    setPasskeyError(null)
    setWalletError(null)
    setSignError(null)
    setPhraseError(null)
  }

  /**
   * API calls for each step of the web wallet process, using the `useApi` hook to
   * manage the state of each call and handle errors.
   */

  // Retrieves attestation options for creating a new passkey
  const { fetch: getCreateOptions } = useApi<{
    token: string
    options: PublicKeyCredentialCreationOptionsJSON
    // Passkey signer setup only; older servers omit it.
    supportedProviders?: string[]
  }>({
    serviceName: 'vault',
    method: 'GET',
    path: 'passkeys/getCreateOptions',
  })

  // Adds the passkey to the database as a signing credential
  const { fetch: addPasskey } = useApi<{
    credentialId: string
  }>({
    serviceName: 'vault',
    method: 'POST',
    path: 'passkeys',
  })

  // Retrieves authentication options for writing to the passkey
  const { fetch: getAuthOptions } = useApi<{
    token: string
    options: PublicKeyCredentialRequestOptionsJSON
  }>({
    serviceName: 'vault',
    method: 'POST',
    path: 'passkeys/getAuthOptions',
  })

  // Retrieves signing options for reading the passkey for signing
  const { fetch: getSignOptions } = useApi<{
    token: string
    options: PublicKeyCredentialRequestOptionsJSON
  }>({
    serviceName: 'vault',
    method: 'POST',
    path: 'passkeys/getSignOptions',
  })

  // Adds the wallet to the database as a signing credential and links it to the passkey
  const { fetch: addWallet } = useApi<{ backupToken?: string }>({
    serviceName: 'vault',
    method: 'PUT',
    path: 'devices/{deviceId}',
  })

  // Adds the signed message to the database for the health check or transaction
  const { fetch: addSignedMessage } = useApi<Signature>({
    serviceName: 'vault',
    method: 'PUT',
    path: 'signatures/{signatureId}',
  })

  // Retrieves the wallet account for the signature to be signed
  const { fetch: getWalletAccount } = useApi<WalletAccount>({
    serviceName: 'vault',
    method: 'GET',
    path: 'walletAccounts/{walletAccountId}',
  })

  // Tracks which walletAccountId the fallback fetch below already attempted,
  // so a failed request is not retried in a render loop.
  const attemptedWalletAccountIdRef = useRef<string | null>(null)

  /**
   * Invalidates in-flight seed reads. `getSeedPhrase` awaits a network call and
   * then a WebAuthn ceremony, so it can resolve long after the flow moved on —
   * for instance after the seed-inactivity expiry cleared secrets and tore down
   * its timer (see useSeedMemoryHygiene). Without this, that late `setPhrase`
   * would drop a fresh mnemonic into context with nothing armed to clear it,
   * and it would sit there until the provider unmounted. Each read captures the
   * counter; `resetPhrase` bumps it, so a superseded read discards its result.
   */
  const phraseReadGenerationRef = useRef(0)

  // Fallback: resolve the PRF signing device even when the caller did not
  // supply a wallet account with populated keys. Transaction signatures have
  // keyId null, so resolvePasskeySigningDeviceId needs walletAccount.keys —
  // fetch the FULL wallet account (GET /walletAccounts/:id without
  // minimize=true; the minimized shape has no keys). The route's
  // canSignWithDevice gate admits the signing-scoped tokens this flow runs
  // under (web/app sessions, sig and ved handoff tokens).
  useEffect(() => {
    if (
      !isPasskeyPrf ||
      jwt == null ||
      passkeySigningDeviceId != null ||
      signature?.key?.deviceId != null ||
      fetchedSigningWalletAccount != null ||
      // Keys are already available — an unresolved device here means several
      // candidates, which the PIN screen's key chooser handles; re-fetching
      // cannot disambiguate.
      (suppliedWalletAccount?.keys?.length ?? 0) > 0
    ) {
      return
    }

    // GET /signatures/:id embeds `key` for health-check signatures and
    // `transaction` for transaction signatures — those are the only two
    // shapes this flow sees, so no other lookup paths are needed.
    const walletAccountId =
      signature?.key?.walletAccountId ??
      signature?.transaction?.walletAccountId ??
      null

    if (
      walletAccountId == null ||
      attemptedWalletAccountIdRef.current === walletAccountId
    ) {
      return
    }
    attemptedWalletAccountIdRef.current = walletAccountId

    void (async () => {
      const [error, result] = await tryCatch(
        getWalletAccount({
          pathData: { walletAccountId },
          token: jwt,
        }),
      )

      if (error != null || result.data == null) {
        // Leave the fallback null — the PIN screen surfaces a clear
        // "unable to determine which passkey key is signing" error rather
        // than guessing a device.
        console.error(
          'Failed to fetch wallet account for passkey signing-device resolution',
          {
            walletAccountId,
            apiErrorCode: result?.error?.code,
            apiErrorMessage: result?.error?.message,
          },
        )
        return
      }

      setFetchedSigningWalletAccount(result.data)
    })()
  }, [
    isPasskeyPrf,
    jwt,
    passkeySigningDeviceId,
    signature,
    suppliedWalletAccount,
    fetchedSigningWalletAccount,
    getWalletAccount,
  ])

  // Creates a new non-syncing, largeBlob supported passkey credential
  const createPasskey = useCallback(async (): Promise<string | null> => {
    // Non-secret ids that tell support which flow and key failed (Datadog only).
    const setupLogContext = {
      flow: 'device_setup',
      deviceType: deviceType ?? null,
      deviceId: deviceId ?? null,
      passkeyPurpose,
    }
    if (jwt == null) {
      setPasskeyError(
        parsePasskeyError({
          context: setupLogContext,
          error: new PasskeyError(
            'missing JWT',
            PasskeyErrorCodes.UNABLE_TO_CONNECT,
          ),
          message: 'missing JWT',
          userId,
        }),
      )
      return null
    }

    setPasskeyError(null)
    setPasskeyLoading(true)

    /**
     * Retrieves attestation options so clients can enforce unique
     *  non-synchronizing passkeys for each device group
     */
    const [attestationOptsError, attestationOptsResult] = await tryCatch(
      getCreateOptions({
        token: jwt,
        query: { purpose: passkeyPurpose, deviceId: deviceId },
      }),
    )

    // Handle remote errors
    if (attestationOptsError != null || attestationOptsResult.data == null) {
      const error = parsePasskeyError({
        context: setupLogContext,
        userId,
        message: 'Failed attestation options request',
        apiResult: attestationOptsResult,
        error: attestationOptsError,
      })

      setPasskeyError(error)
      setPasskeyLoading(false)
      return null
    }

    // Extract the token and options from the response
    const { token, options } = attestationOptsResult.data
    setSupportedProviders(
      readSupportedProviders(attestationOptsResult.data.supportedProviders),
    )

    const [registrationError, registrationResponse] = await tryCatch(
      passkeyUtils.createRawCredential(options),
    )

    // Handles errors from the browser prompt for passkey registration
    if (registrationError != null) {
      const error = parsePasskeyError({
        context: setupLogContext,
        userId,
        message: 'Failed to create passkey from browser prompt',
        error: registrationError,
      })

      setPasskeyError(error)
      setPasskeyLoading(false)
      return null
    }

    // Add the credential to the users account
    // Only bind deviceId at creation time for platform-passkey (PRF) devices.
    // YubiKey passkeys are created unbound (deviceId: null) and associated later
    // via the separate associatePasskeyWithDevice / PUT /devices/:id flow.
    const [addPasskeyError, addPasskeyResult] = await tryCatch(
      addPasskey({
        body: {
          options: token,
          attestation: registrationResponse as AnyObject,
          name: walletName,
          purpose: passkeyPurpose,
          ...(isPasskeyPrf && deviceId != null && deviceId !== ''
            ? { deviceId }
            : {}),
        },
        token: jwt,
      }),
    )

    // Handle errors from adding the passkey to the database
    if (
      addPasskeyError != null ||
      addPasskeyResult.data?.credentialId == null
    ) {
      const error = parsePasskeyError({
        context: setupLogContext,
        userId,
        message: 'Creation successful, unable to add to database',
        apiResult: addPasskeyResult,
        error: addPasskeyError,
      })

      setPasskeyError(error)
      setPasskeyLoading(false)
      return null
    }

    // Set the credentialId for the next step in the process
    const newCredentialId = addPasskeyResult.data.credentialId
    setCredentialId(newCredentialId)
    setPasskeyLoading(false)
    return newCredentialId
  }, [
    jwt,
    addPasskey,
    getCreateOptions,
    deviceId,
    passkeyPurpose,
    walletName,
    isPasskeyPrf,
    userId,
    deviceType,
  ])

  const getSeedPhrase = useCallback(
    async (
      passphrase?: string,
      recoveryDevice?: Pick<Device, 'xpub' | 'hardenedKeyPathPurpose'>,
    ) => {
      // Non-secret ids that tell support which flow and key failed (Datadog only).
      const exportLogContext = {
        flow: 'device_export',
        deviceType: deviceType ?? null,
        deviceId: device?.id ?? deviceId ?? null,
        passkeyPurpose,
      }
      if (jwt == null || (credentialId == null && deviceId == null)) {
        setPhraseError(
          parsePasskeyError({
            context: exportLogContext,
            error: new PasskeyError(
              'missing JWT',
              PasskeyErrorCodes.UNAUTHORIZED,
            ),
            message: 'missing JWT',
            userId,
          }),
        )

        return
      }

      const readGeneration = ++phraseReadGenerationRef.current
      const isCurrentRead = (): boolean =>
        readGeneration === phraseReadGenerationRef.current

      setPhraseLoading(true)
      setPhraseError(null)
      setPhrase(null)
      setPhraseConfirmed(false)
      try {
        // Get the authentication options for signing the transaction
        const [signOptionsError, signOptionsResult] = await tryCatch(
          getSignOptions({
            query: {
              deviceId: device?.id ?? deviceId,
            },
            token: backupToken ?? jwt,
          }),
        )

        // Handle errors from the server
        if (signOptionsError != null || signOptionsResult.error != null) {
          const error = parsePasskeyError({
            context: exportLogContext,
            userId,
            message: 'Failed to get auth options to read blob',
            apiResult: signOptionsResult,
            error: signOptionsError,
          })

          setPhraseError(error)
          return
        }

        if (isPasskeyPrf) {
          // The PRF-passkey recovery flow (PasskeyRecovery.tsx) always has a
          // real passphrase by the time it calls getSeedPhrase — it's only
          // released after PIN entry + 2FA step-up + releasePassphrase()
          // succeed. An empty/missing value here would silently derive the
          // WRONG mnemonic from an empty BIP-39 passphrase, so this path must
          // fail loudly instead of falling back to ''.
          if (passphrase == null || passphrase === '') {
            setPhraseError(
              parsePasskeyError({
                context: exportLogContext,
                error: new PasskeyError(
                  'Attempted to derive PRF passkey seed phrase without a passphrase',
                  PasskeyErrorCodes.INCORRECT_STATE,
                ),
                message:
                  'Attempted to derive PRF passkey seed phrase without a passphrase',
                userId,
              }),
            )
            return
          }

          // Resolve credentialId from allowCredentials if not already set
          const resolvedPhraseCredentialId =
            credentialId ??
            signOptionsResult.data.options.allowCredentials?.[0]?.id

          if (
            resolvedPhraseCredentialId == null ||
            resolvedPhraseCredentialId === ''
          ) {
            setPhraseError(
              parsePasskeyError({
                context: exportLogContext,
                error: new PasskeyError(
                  'Missing credential for passkey recovery',
                  PasskeyErrorCodes.INCORRECT_STATE,
                ),
                message: 'Missing credential for passkey recovery',
                userId,
              }),
            )
            return
          }

          // A setup backup uses the xpub accepted by addWallet. Emailed
          // recovery retains the device fetched before the handoff token expires.
          const expectedDevice = recoveryDevice ?? device

          // PRF-based: derive seed phrase on the fly
          const [readError, readSeed] = await tryCatch(
            getSeedPhraseForRecovery({
              authenticationOptions: signOptionsResult.data.options,
              credentialId: resolvedPhraseCredentialId,
              passphrase,
              expectedXpub: xPub ?? expectedDevice?.xpub ?? '',
              // Pair the purpose with the xpub it checks: the purpose of the
              // export that set xPub, else the device's stored purpose.
              hardenedKeyPathPurpose:
                xPub != null
                  ? xPubHardenedKeyPathPurpose
                  : expectedDevice?.hardenedKeyPathPurpose,
            }),
          )

          if (readError != null || readSeed == null) {
            const error = parsePasskeyError({
              context: exportLogContext,
              userId,
              message: 'Failed to derive seed phrase from passkey PRF',
              error: readError,
            })
            setPhraseError(error)
            return
          }

          if (!isCurrentRead()) {
            // Superseded (expiry or an explicit reset). Drop the mnemonic.
            return
          }

          setPhrase(readSeed.mnemonic.split(' '))
        } else {
          // largeBlob-based: read stored seed
          const [readError, readSeed] = await tryCatch(
            getStoredSeed({
              authenticationOptions: signOptionsResult.data.options,
            }),
          )

          if (readError != null || readSeed == null) {
            const error = parsePasskeyError({
              context: exportLogContext,
              userId,
              message: 'Failed to read seed phrase from passkey prompt',
              error: readError,
            })
            setPhraseError(error)
            return
          }

          if (!isCurrentRead()) {
            // Superseded (expiry or an explicit reset). Drop the mnemonic.
            return
          }

          setPhrase(readSeed.split(' '))
        }
      } finally {
        // Clear the loading flag on EVERY exit — the success paths and the
        // superseded-read returns never did, so the context reported a read
        // still in flight forever. Guarded by isCurrentRead so a read that has
        // already been superseded cannot clear the flag belonging to the newer
        // read that replaced it.
        if (isCurrentRead()) {
          setPhraseLoading(false)
        }
      }
    },
    [
      jwt,
      credentialId,
      deviceId,
      device,
      backupToken,
      getSignOptions,
      isPasskeyPrf,
      userId,
      deviceType,
      xPub,
      xPubHardenedKeyPathPurpose,
      passkeyPurpose,
    ],
  )

  /**
   * Writes the xpub to the wallet and links it to the passkey,
   * must be called once a credentialId is available from the passkey creation
   * process.
   */
  const createWallet = useCallback(
    async (
      seedPhrase?: string,
      passphrase?: string,
      prfPassphrase?: string,
    ) => {
      // Non-secret ids that tell support which flow and key failed (Datadog only).
      const xpubExportLogContext = {
        flow: 'xpub_export',
        deviceType: deviceType ?? null,
        deviceId: device?.id ?? null,
        passkeyPurpose,
      }
      if (jwt == null || credentialId == null || device == null) {
        setWalletError(
          parsePasskeyError({
            context: xpubExportLogContext,
            error: new PasskeyError(
              'Attempted to create wallet before JWT, credentialId, and device are available',
              PasskeyErrorCodes.INCORRECT_STATE,
            ),
            message:
              'Attempted to create wallet before JWT, credentialId, and device are available',
            userId,
          }),
        )
        return
      }

      // The PRF-passkey setup flow (PasskeyRegister.tsx) always has a real
      // passphrase by the time it calls createWallet — it's only available
      // after PIN creation + setupPassphrase() succeed. An empty/missing
      // value here would silently derive a wallet from an empty BIP-39
      // passphrase, so this path must fail loudly instead.
      if (isPasskeyPrf && (prfPassphrase == null || prfPassphrase === '')) {
        setWalletError(
          parsePasskeyError({
            context: xpubExportLogContext,
            error: new PasskeyError(
              'Attempted to create PRF passkey wallet without a passphrase',
              PasskeyErrorCodes.INCORRECT_STATE,
            ),
            message:
              'Attempted to create PRF passkey wallet without a passphrase',
            userId,
          }),
        )
        return
      }

      setWalletError(null)
      setWalletLoading(true)

      // Get auth options to WRITE to the passkey largeBlob.
      // Forward the vault-setup JWT as the Bearer token so optionalAuthUser()
      // can authenticate — the controller's credentialId + purpose=sign path
      // requires req.user to be set.
      const [authOptionsError, authOptionsResult] = await tryCatch(
        getAuthOptions({
          body: {
            credentialId,
          },
          query: {
            purpose: passkeyPurpose,
            deviceId,
          },
          token: jwt,
        }),
      )

      // Handle errors from the server
      if (authOptionsError != null || authOptionsResult.data == null) {
        const error = parsePasskeyError({
          context: xpubExportLogContext,
          userId,
          message: 'Failed to get auth options to write blob',
          apiResult: authOptionsResult,
          error: authOptionsError,
        })

        setWalletError(error)
        setWalletLoading(false)
        return
      }

      const { token, options } = authOptionsResult.data

      // Export the xpub from the passkey
      let xPubExport: {
        xpub: string
        authenticationResponse: AuthenticationResponseJSON
        blobVersion?: string
        derivationVersion?: string
      }

      if (isPasskeyPrf) {
        const [xPubError, xPubResult] = await tryCatch(
          passkeyPrfDevice.exportXpub({
            hardenedKeyPathPurpose: passkeyPrfHardenedKeyPathPurpose,
            authenticationOptions: options,
            credentialId,
            // PRF-device BIP-39 passphrase (device-signing v3 derivation:
            // 12 words + passphrase), gated by PIN. Guaranteed non-empty above.
            passphrase: prfPassphrase as string,
          }),
        )

        if (xPubError != null) {
          const error = parsePasskeyError({
            context: xpubExportLogContext,
            userId,
            message: 'Failed to export xpub from passkey PRF',
            error: xPubError,
          })

          setWalletError(error)
          setWalletLoading(false)
          return
        }

        xPubExport = xPubResult
      } else {
        const [xPubError, xPubResult] = await tryCatch(
          passkeyDevice.exportXpub({
            hardenedKeyPathPurpose: device.hardenedKeyPathPurpose,
            authenticationOptions: options,
            credentialId,
            seedPhrase,
          }),
        )

        if (xPubError != null) {
          const error = parsePasskeyError({
            context: xpubExportLogContext,
            userId,
            message: 'Failed to export xpub from passkey',
            error: xPubError,
          })

          setWalletError(error)
          setWalletLoading(false)
          return
        }

        xPubExport = xPubResult
      }

      const exportedHardenedKeyPathPurpose = isPasskeyPrf
        ? passkeyPrfHardenedKeyPathPurpose
        : device.hardenedKeyPathPurpose

      setDeviceUpdateLoading(true)

      // Update the device on the server
      const [addWalletError, addWalletResult] = await tryCatch(
        addWallet({
          pathData: {
            deviceId,
          },
          body: {
            xpub: xPubExport.xpub,
            token,
            authenticationResponse:
              xPubExport.authenticationResponse as AnyObject,
            deviceType: isPasskeyPrf
              ? DEVICE_TYPE.PASSKEY
              : DEVICE_TYPE.YUBIKEY,
            ...(isPasskeyPrf
              ? { derivationVersion: xPubExport.derivationVersion }
              : { blobVersion: xPubExport.blobVersion }),
            hardenedKeyPathPurpose: exportedHardenedKeyPathPurpose,
          },
          token: jwt,
        }),
      )

      // Handle errors from the server
      if (addWalletError != null || addWalletResult.error != null) {
        const error = parsePasskeyError({
          context: xpubExportLogContext,
          userId,
          message:
            'Seed phrase written to passkey, but API call failed to update device',
          error: addWalletError,
          apiResult: addWalletResult,
        })

        setWalletError(error)
        setDeviceUpdateLoading(false)
        setWalletLoading(false)
        return
      }

      // The device update just revoked the single-use exp handoff token (see
      // device.controller `revokeToken`) and returned a fresh backupToken for
      // any follow-up seed-phrase read — getSeedPhrase reads `backupToken ??
      // jwt`, and the jwt is now dead. That read only happens if the user
      // opts into the backup screen (PasskeyBackup derives the mnemonic on
      // demand), but commit the continuation token before xPub anyway so no
      // xPub-gated consumer can ever observe the revoked-jwt state.
      setBackupToken(addWalletResult.data?.backupToken)
      setXPubHardenedKeyPathPurpose(exportedHardenedKeyPathPurpose)
      setXPub(xPubExport.xpub)
      setWalletLoading(false)
      return
    },
    [
      credentialId,
      jwt,
      deviceId,
      addWallet,
      getAuthOptions,
      device,
      isPasskeyPrf,
      passkeyPrfHardenedKeyPathPurpose,
      passkeyPurpose,
      userId,
      deviceType,
    ],
  )

  /**
   * Writes a seed phrase to the YubiKey largeBlob WITHOUT calling PUT /devices/:id.
   * Used by the seed import flow where device transition is deferred until after health check.
   * Returns the export data needed to later call PUT /devices/:id.
   */
  const writeSeedToYubiKey = useCallback(
    async (
      seedPhrase: string,
      passphrase?: string,
    ): Promise<YubiKeyExportData | null> => {
      // Non-secret ids that tell support which flow and key failed (Datadog only).
      const seedImportLogContext = {
        flow: 'seed_import',
        deviceType: deviceType ?? null,
        deviceId: device?.id ?? deviceId ?? null,
      }
      if (jwt == null || credentialId == null || device == null) {
        setWalletError(
          parsePasskeyError({
            context: seedImportLogContext,
            error: new PasskeyError(
              'Attempted to write seed before JWT, credentialId, and device are available',
              PasskeyErrorCodes.INCORRECT_STATE,
            ),
            message:
              'Attempted to write seed before JWT, credentialId, and device are available',
            userId,
          }),
        )
        return null
      }

      setWalletError(null)
      setWalletLoading(true)

      // Get auth options to WRITE to the passkey largeBlob.
      // Forward the seed-import JWT as the Bearer token so optionalAuthUser()
      // can authenticate, and scope the request to deviceId so the controller's
      // handoff check (assertHandoffTokenMatchesCredential) passes for the
      // still-unbound YubiKey credential.
      const [authOptionsError, authOptionsResult] = await tryCatch(
        getAuthOptions({
          body: { credentialId },
          query: {
            // writeSeedToYubiKey is only used by the YubiKey seed-import flow
            // (see YubikeyImport.tsx), never the passkey PRF flow, so the
            // purpose is always the YubiKey 'sign' purpose.
            purpose: 'sign',
            deviceId,
          },
          token: jwt,
        }),
      )

      if (authOptionsError != null || authOptionsResult.data == null) {
        const error = parsePasskeyError({
          context: seedImportLogContext,
          userId,
          message: 'Failed to get auth options to write blob',
          apiResult: authOptionsResult,
          error: authOptionsError,
        })

        setWalletError(error)
        setWalletLoading(false)
        return null
      }

      const { token, options } = authOptionsResult.data

      // Export the xpub from the passkey (writes seed to largeBlob)
      const [xPubError, xPubExport] = await tryCatch(
        passkeyDevice.exportXpub({
          hardenedKeyPathPurpose: device.hardenedKeyPathPurpose,
          authenticationOptions: options,
          credentialId,
          seedPhrase,
          passphrase,
        }),
      )

      if (xPubError != null) {
        const error = parsePasskeyError({
          context: seedImportLogContext,
          userId,
          message: 'Failed to export xpub from passkey',
          error: xPubError,
        })

        setWalletError(error)
        setWalletLoading(false)
        return null
      }

      setXPubHardenedKeyPathPurpose(device.hardenedKeyPathPurpose)
      setXPub(xPubExport.xpub)
      setWalletLoading(false)

      return {
        xpub: xPubExport.xpub,
        authenticationResponse: xPubExport.authenticationResponse,
        blobVersion: xPubExport.blobVersion,
        token,
      }
    },
    [credentialId, jwt, deviceId, getAuthOptions, device, userId, deviceType],
  )

  /**
   * Signs the health check message with the passkey, must be called once the xpub
   * is available from the wallet creation process
   */
  const signHealthCheck = useCallback(
    async (prfPassphrase?: string) => {
      // Check for required inputs to sign the health check
      if (jwt == null || signature?.key?.walletAccountId == null) {
        setWalletError(
          parsePasskeyError({
            error: new PasskeyError(
              'Unable to sign health check without JWT and walletAccountId from signature key',
              PasskeyErrorCodes.INCORRECT_STATE,
            ),
            message:
              'Unable to sign health check without JWT and walletAccountId from signature key',
            userId,
          }),
        )
        return
      }

      // The PRF-passkey health-check flow (PasskeySign.tsx) always has a real
      // passphrase by the time it calls signHealthCheck — it's only released
      // after PIN entry + releasePassphrase() succeed. An empty/missing value
      // here would silently derive a signing key from an empty BIP-39
      // passphrase, producing a WRONG signature, so this path must fail
      // loudly instead of falling back to ''.
      if (isPasskeyPrf && (prfPassphrase == null || prfPassphrase === '')) {
        setSignError(
          parsePasskeyError({
            error: new PasskeyError(
              'Attempted to sign PRF passkey health check without a passphrase',
              PasskeyErrorCodes.INCORRECT_STATE,
            ),
            message:
              'Attempted to sign PRF passkey health check without a passphrase',
            userId,
          }),
        )
        return
      }

      setSignError(null)
      setHealthCheckAuthenticatorAttachment(null)
      setSignatureLoading(true)

      // Tags the health-check failure logs so support can tell which key and
      // flow failed. allowCredentialCount 0 means the server found no
      // credential for the caller, so the browser falls back to its picker.
      const healthCheckLogContext: Record<string, string | number | null> = {
        flow: 'health_check',
        deviceType: deviceType ?? null,
        signatureId: signature.id,
        deviceId: signature.key?.deviceId ?? null,
        passkeyPurpose,
      }

      // A PRF health check is always for one specific key, and the PRF-derived
      // seed is specific to the credential that asserts — so scope the auth
      // options to that key's device. Requesting by signatureId instead
      // returns every signing passkey in the device group (in arbitrary DB
      // order), and taking the first one asks the browser for a credential it
      // may not hold ("You don't have a passkey") or derives a seed from a
      // sibling key's credential. The YubiKey path keeps the signatureId
      // (group-wide) request: any YubiKey in the group may submit, and the
      // server warns if a different device signed.
      const healthCheckDeviceId = isPasskeyPrf
        ? signature.key?.deviceId ?? null
        : null

      // Get the authentication options for signing the health check. The
      // signatureId is always sent: a bare-deviceId request is treated by the
      // server as a seed export and logged to the audit trail, while a
      // deviceId paired with the signature it fulfills is recognized as a
      // signing flow (the server validates the pairing).
      const [authOptionsError, authOptionsResult] = await tryCatch(
        getSignOptions(
          healthCheckDeviceId != null
            ? {
                query: {
                  purpose: passkeyPurpose,
                  deviceId: healthCheckDeviceId,
                },
                body: { signatureId: signature.id },
                token: jwt,
              }
            : {
                query: { purpose: passkeyPurpose },
                body: { signatureId: signature.id },
                token: jwt,
              },
        ),
      )

      // Handle errors from the server
      if (authOptionsError != null || authOptionsResult.data == null) {
        const error = parsePasskeyError({
          userId,
          message: 'Failed to get auth options to read blob for health check',
          apiResult: authOptionsResult,
          error: authOptionsError,
          context: healthCheckLogContext,
        })

        setSignError(error)
        setSignatureLoading(false)
        return
      }

      const { options } = authOptionsResult.data

      // With deviceId-scoped options, the returned allowCredentials belong to
      // the target device, so the first entry is the right credential. Without
      // a deviceId, pass null so the PRF device presents the full server list
      // and the browser filters to a credential it actually holds.
      const resolvedCredentialId =
        credentialId ??
        (healthCheckDeviceId != null
          ? options.allowCredentials?.[0]?.id ?? null
          : null)

      // Get the wallet account for the signature
      const [walletAccountError, walletAccountResult] = await tryCatch(
        getWalletAccount({
          pathData: { walletAccountId: signature.key?.walletAccountId },
          /**
           * This query allows for a minimized response from the server, enabling
           * inheritance recipients to complete the health check
           */
          query: { minimize: true },
          token: jwt,
        }),
      )

      // Handle errors from the server
      if (walletAccountError != null || walletAccountResult.data == null) {
        const error = parsePasskeyError({
          userId,
          context: healthCheckLogContext,
          message: 'Failed to get wallet account for health check',
          apiResult: walletAccountResult,
          error: walletAccountError,
        })

        setSignError(error)
        setSignatureLoading(false)
        return
      }

      const walletAccount = walletAccountResult.data
      const isEth = ETH_COIN_TYPES.includes(walletAccount.coinType)

      // The cosigner Key's path fields are the source of truth for the signing
      // path — walletAccount describes the wallet type, which can diverge from
      // the cosigner's actual derivation (e.g. hardened BIP-45 cosigner xpub in
      // a BIP-49-typed multisig). Surface a recoverable error if `signature.key`
      // is unexpectedly null rather than silently falling back to walletAccount.
      if (signature.key == null) {
        const error = parsePasskeyError({
          userId,
          message:
            'Signature is missing key data — cannot derive signing path.',
        })
        setSignError(error)
        setSignatureLoading(false)
        return
      }

      // Sign the health check message with the passkey. The cosigner Key's
      // path fields (signature.key) are the source of truth for the signing
      // path, not walletAccount — see the null-check above.
      const signCall: Promise<{
        signedMessage: string
        authenticatorAttachment?: AuthenticatorAttachmentResult
      }> = isPasskeyPrf
        ? passkeyPrfDevice.getSignedMessageWithAttachment({
            coin: isEth ? 'ETH' : 'BTC',
            keyPathPurpose: signature.key.keyPathPurpose,
            keyPathPurposeIsHardened:
              signature.key.keyPathPurposeIsHardened ?? false,
            keyPathCoinType: signature.key.keyPathCoinType,
            keyPathAccount: signature.key.keyPathAccount,
            message: signature.id,
            authenticationOptions: options,
            credentialId: resolvedCredentialId,
            // PRF-device BIP-39 passphrase (device-signing v3 derivation:
            // 12 words + passphrase), gated by PIN. Guaranteed non-empty above.
            passphrase: prfPassphrase as string,
          })
        : passkeyDevice
            .getSignedMessage({
              coin: isEth ? 'ETH' : 'BTC',
              keyPathPurpose: signature.key.keyPathPurpose,
              keyPathPurposeIsHardened:
                signature.key.keyPathPurposeIsHardened ?? false,
              keyPathCoinType: signature.key.keyPathCoinType,
              keyPathAccount: signature.key.keyPathAccount,
              message: signature.id,
              authenticationOptions: options,
            })
            .then((signedMessage) => ({ signedMessage }))

      const [signatureError, signResult] = await tryCatch(signCall)

      // Handle errors from executing the passkey signing
      if (signatureError != null) {
        const error = parsePasskeyError({
          userId,
          message: 'Failed to sign health check message',
          error: signatureError,
          context: {
            ...healthCheckLogContext,
            allowCredentialCount: options.allowCredentials?.length ?? 0,
          },
        })

        setSignError(error)
        setSignatureLoading(false)
        return
      }

      const { signedMessage, authenticatorAttachment } = signResult

      // Add the signed message to the server. Only the PRF passkey path
      // reports how the credential was presented (platform vs
      // cross-platform); null is sent as-is when the browser doesn't say.
      // isMobileDevice tells the server about an iPad that sends a Mac user
      // agent, so it does not count as a desktop backup proof.
      const [submissionError, submissionResult] = await tryCatch(
        addSignedMessage({
          body: {
            externalSignatures: [signedMessage],
            deviceType: isPasskeyPrf
              ? DEVICE_TYPE.PASSKEY
              : DEVICE_TYPE.YUBIKEY,
            ...(isPasskeyPrf
              ? {
                  authenticatorAttachment: authenticatorAttachment ?? null,
                  isMobileDevice: IS_MOBILE_DEVICE,
                }
              : {}),
          },
          pathData: { signatureId: signature.id },
          token: jwt,
        }),
      )

      // Handle errors from the server
      if (
        submissionError != null ||
        submissionResult.data?.signedData == null
      ) {
        const error = parsePasskeyError({
          userId,
          message: 'Failed to submit signed health check message',
          apiResult: submissionResult,
          error: submissionError,
          context: healthCheckLogContext,
        })

        setSignError(error)
        setSignatureLoading(false)
        return
      }

      const { showNotification, intendedLocationType, actualLocationType } =
        verifySignatureLocationType({
          signature,
          addSignatureResult: submissionResult,
        })

      if (showNotification) {
        toast.error(
          wrongKeyMessage(translateToString, {
            actualLocationType,
            intendedLocationType,
            keyLabels: walletAccount.keyLabels,
          }),
        )
      }

      setHealthCheckAuthenticatorAttachment(authenticatorAttachment ?? null)
      setSignatureResult(submissionResult.data.signedData)
      setSignatureLoading(false)
    },
    [
      jwt,
      getSignOptions,
      addSignedMessage,
      getWalletAccount,
      signature,
      translateToString,
      isPasskeyPrf,
      passkeyPurpose,
      credentialId,
      userId,
      deviceType,
    ],
  )

  const signTransaction = useCallback(
    async (prfPassphrase?: string) => {
      // Non-secret ids that tell support which flow and key failed (Datadog only).
      const signingLogContext = {
        flow: 'transaction_signing',
        deviceType: deviceType ?? null,
        signatureId: transactionInputs?.signature?.id ?? null,
        deviceId: passkeySigningDeviceId ?? null,
        passkeyPurpose,
      }
      // Validate required inputs for signing a transaction
      if (jwt == null || transactionInputs == null) {
        setSignError(
          parsePasskeyError({
            context: signingLogContext,
            error: new PasskeyError(
              'Cannot sign transaction without JWT and transaction inputs',
              PasskeyErrorCodes.INCORRECT_STATE,
            ),
            message:
              'Cannot sign transaction without JWT and transaction inputs',
            userId,
          }),
        )
        return
      }

      // Renamed to txSignature so the provider-level `signature` prop (used by
      // the PIN-release step, which always carries key.deviceId in the PRF
      // flow) stays reachable below — transaction Signature rows often come
      // back without their `key` association populated.
      const {
        walletAccount,
        signature: txSignature,
        toSign,
        isTestnet,
      } = transactionInputs

      // Validate required inputs for signing a transaction
      if (walletAccount == null || txSignature == null || toSign == null) {
        setSignError(
          parsePasskeyError({
            context: signingLogContext,
            error: new PasskeyError(
              'Transaction inputs require walletAccount, signature, and toSign data',
              PasskeyErrorCodes.INCORRECT_STATE,
            ),
            message:
              'Transaction inputs require walletAccount, signature, and toSign data',
            userId,
          }),
        )
        return
      }

      // The PRF-passkey signing flow (PasskeySign.tsx) always has a real
      // passphrase by the time it calls signTransaction — it's only released
      // after PIN entry + releasePassphrase() succeed. An empty/missing value
      // here would silently derive a signing key from an empty BIP-39
      // passphrase, producing a WRONG signature, so this path must fail
      // loudly instead of falling back to ''.
      if (isPasskeyPrf && (prfPassphrase == null || prfPassphrase === '')) {
        setSignError(
          parsePasskeyError({
            context: signingLogContext,
            error: new PasskeyError(
              'Attempted to sign PRF passkey transaction without a passphrase',
              PasskeyErrorCodes.INCORRECT_STATE,
            ),
            message:
              'Attempted to sign PRF passkey transaction without a passphrase',
            userId,
          }),
        )
        return
      }

      setSignError(null)
      setSignatureLoading(true)

      // A transaction signature belongs to one specific key, and the PRF
      // seed is specific to the credential that asserts — scope the auth
      // options to that key's device when it is known. Requesting by
      // signatureId returns every signing passkey across the vault's devices
      // (in arbitrary DB order), so taking the first entry can name a
      // credential this browser doesn't hold ("You don't have a passkey") or
      // a sibling key's credential. passkeySigningDeviceId is the same device
      // the PIN release used (transaction Signature rows have keyId null, so
      // it is resolved from the wallet account's passkey keys), keeping the
      // released passphrase and the prompted credential on one device. When
      // it can't be resolved, keep the signatureId request and pass the full
      // allowCredentials list through so the browser filters to credentials
      // it holds and the user selects. The YubiKey path keeps the group-wide
      // request either way.
      const txDeviceId = isPasskeyPrf
        ? passkeySigningDeviceId ?? txSignature.key?.deviceId ?? null
        : null

      // Get the authentication options for signing the transaction. The
      // signatureId is always sent: a bare-deviceId request is treated by the
      // server as a seed export and logged to the audit trail, while a
      // deviceId paired with the signature it fulfills is recognized as a
      // signing flow (the server validates the pairing).
      const [authOptionsError, authOptionsResult] = await tryCatch(
        getSignOptions(
          txDeviceId != null
            ? {
                query: { purpose: passkeyPurpose, deviceId: txDeviceId },
                body: { signatureId: txSignature.id },
                token: jwt,
              }
            : {
                query: { purpose: passkeyPurpose },
                body: { signatureId: txSignature.id },
                token: jwt,
              },
        ),
      )

      // Handle errors from the server
      if (authOptionsError != null || authOptionsResult.data == null) {
        const error = parsePasskeyError({
          context: signingLogContext,
          userId,
          message: 'Failed to get auth options to read blob for transaction',
          apiResult: authOptionsResult,
          error: authOptionsError,
        })

        setSignError(error)
        setSignatureLoading(false)
        return
      }

      // With deviceId-scoped options the first allowCredential is the target
      // device's own credential; otherwise pass null so the PRF device
      // presents the full server list (see getPrfOutput).
      const resolvedTxCredentialId =
        credentialId ??
        (txDeviceId != null
          ? authOptionsResult.data.options.allowCredentials?.[0]?.id ?? null
          : null)

      const signParams = formatSignTxParams({
        selectedDevice: isPasskeyPrf
          ? DEVICE_TYPE.PASSKEY
          : DEVICE_TYPE.YUBIKEY,
        walletAccount,
        signature: txSignature,
        toSign,
        token: jwt,
        isTestnet,
      })

      // Sign the transaction with the passkey
      const signCall = isPasskeyPrf
        ? passkeyPrfDevice.signTransaction({
            ...signParams,
            device: PASSKEY_DEVICES.PASSKEY,
            authenticationOptions: authOptionsResult.data.options,
            credentialId: resolvedTxCredentialId,
            // PRF-device BIP-39 passphrase (device-signing v3 derivation:
            // 12 words + passphrase), gated by PIN. Guaranteed non-empty above.
            passphrase: prfPassphrase as string,
          })
        : passkeyDevice.signTransaction({
            ...signParams,
            device: PASSKEY_DEVICES.YUBIKEY,
            authenticationOptions: authOptionsResult.data.options,
          })

      const [signatureError, signatures] = await tryCatch(signCall)

      // Handle errors from the passkey signing in browser
      if (signatureError != null) {
        const error = parsePasskeyError({
          context: signingLogContext,
          userId,
          message: 'Failed to sign transaction with passkey',
          error: signatureError,
        })

        setSignError(error)
        setSignatureLoading(false)
        return
      }

      const [submissionError, submissionResult] = await tryCatch(
        addSignedMessage({
          body: {
            externalSignatures: Array.isArray(signatures)
              ? signatures
              : [signatures],
            deviceType: isPasskeyPrf
              ? PASSKEY_DEVICES.PASSKEY
              : PASSKEY_DEVICES.YUBIKEY,
          },
          pathData: { signatureId: txSignature.id },
          token: jwt,
        }),
      )

      if (
        submissionError != null ||
        submissionResult.data?.signedData == null
      ) {
        const error = parsePasskeyError({
          context: signingLogContext,
          userId,
          message: 'Signing successful, but failed to submit to server',
          apiResult: submissionResult,
          error: submissionError,
        })

        setSignError(error)
        setSignatureLoading(false)
        return
      }

      const { showNotification, intendedLocationType, actualLocationType } =
        verifySignatureLocationType({
          signature: txSignature,
          addSignatureResult: submissionResult,
        })

      if (showNotification) {
        toast.error(
          wrongKeyMessage(translateToString, {
            actualLocationType,
            intendedLocationType,
            keyLabels:
              walletAccount.keyLabels ?? fetchedSigningWalletAccount?.keyLabels,
          }),
        )
      }

      setSignatureResult(submissionResult.data.signedData)
      setSignatureLoading(false)
    },
    [
      jwt,
      getSignOptions,
      addSignedMessage,
      transactionInputs,
      translateToString,
      isPasskeyPrf,
      passkeyPurpose,
      credentialId,
      passkeySigningDeviceId,
      userId,
      deviceType,
      fetchedSigningWalletAccount,
    ],
  )

  const onConfirmPhrase = useCallback(() => {
    setPhraseConfirmed(true)
  }, [])

  // Clears the derived 12-word mnemonic from context state. Consumers call this
  // on success/error/unmount so the mnemonic (and the passphrase shown beside
  // it during backup/recovery) does not linger in a live React tree after the
  // flow completes.
  const resetPhrase = useCallback(() => {
    // Bump first so any read still in flight discards its result instead of
    // repopulating the phrase we are clearing.
    phraseReadGenerationRef.current += 1
    setPhrase(null)
    setPhraseConfirmed(false)
    // A cancel, so nothing is in flight any more. getSeedPhrase's own finally
    // cannot do this: it only clears the flag when its read is still current,
    // which a read superseded by THIS call is not — so without clearing here,
    // the flag would stay set with no read left to own it.
    setPhraseLoading(false)
  }, [])

  return (
    <WebWalletContext.Provider
      value={{
        xPub,
        signature,
        passkeySigningDeviceId,
        passkeySigningKeyCandidates,
        signingKeyLabels: signingWalletAccount?.keyLabels,
        selectPasskeySigningDevice: setSelectedSigningDeviceId,
        signatureResult,
        healthCheckAuthenticatorAttachment,
        createPasskey,
        createWallet,
        writeSeedToYubiKey,
        supportedProviders,
        passkeyError,
        walletError,
        passkeyLoading,
        walletLoading,
        deviceUpdateLoading,
        signatureLoading,
        credentialId,
        resetErrors,
        isHealthCheck: Boolean(isHealthCheck),
        isTransaction: Boolean(isTransaction),
        signTransaction,
        signHealthCheck,
        signError,
        getSeedPhrase,
        phrase,
        phraseLoading,
        phraseError,
        phraseConfirmed,
        onConfirmPhrase,
        resetPhrase,
        setBackupToken,
        backupToken,
      }}
    >
      {children}
    </WebWalletContext.Provider>
  )
}

export function useWebWallet(): WebWalletState {
  return useContext(WebWalletContext)
}
