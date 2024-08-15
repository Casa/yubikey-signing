import { efwAsync } from '@casa/common/src/lib/errorFirstWrap'
import * as passkeyDevice from '@casa/device-signing/src/passkeyDevice'
import { getStoredSeed } from '@casa/device-signing/src/passkeyDevice'
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
import {
  useState,
  createContext,
  ReactElement,
  ReactNode,
  useContext,
  useCallback,
} from 'react'
import toast from 'react-hot-toast'
import { useParams } from 'react-router-dom'
import { StringParam, useQueryParam } from 'use-query-params'
import { AnyObject } from 'yup/lib/types'

import { DEVICE_TYPE, Device, LOCATION_TYPE_LABEL } from 'src/constants/device'
import { Signature } from 'src/constants/signature'
import {
  COIN_TYPE,
  ETH_COIN_TYPES,
  WalletAccount,
} from 'src/constants/wallet-accounts'
import { parsePasskeyError } from 'src/features/device-signing/utils/parseError'
import {
  formatSignTxParams,
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
const PASSKEY_PURPOSE = 'sign'

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

type WebWalletState = {
  createPasskey: () => Promise<void>
  createWallet: () => Promise<void>
  signHealthCheck: () => Promise<void>
  signTransaction: () => Promise<void>
  getSeedPhrase: () => Promise<void>
  onConfirmPhrase: () => void
  resetErrors: () => void
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
  credentialId: string | null
  xPub: string | null
  phrase: string[] | null
  signatureResult: string | null
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
  signature,
  transactionInputs,
  isHealthCheck,
  isTransaction,
  children,
}: {
  device?: Device
  signature?: Signature
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
  const [walletError, setWalletError] = useState<PasskeyError | null>(null)
  const [signError, setSignError] = useState<PasskeyError | null>(null)
  const [phraseError, setPhraseError] = useState<PasskeyError | null>(null)

  // Success states for each step of the web wallet process
  const [credentialId, setCredentialId] = useState<string | null>(null)
  const [xPub, setXPub] = useState<string | null>(null)
  const [backupToken, setBackupToken] = useState<string | undefined>()
  const [signatureResult, setSignatureResult] = useState<string | null>(null)
  const [phrase, setPhrase] = useState<string[] | null>(null)
  const [phraseConfirmed, setPhraseConfirmed] = useState<boolean>(false)

  // Url parameters for the web wallet setup process
  const [jwt] = useQueryParam('jwt', StringParam)
  const { deviceId } = useParams<{ deviceId: string; jwt: string }>()
  const { translateToString } = useTranslate()

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

  // Creates a new non-syncing, largeBlob supported passkey credential
  const createPasskey = useCallback(async () => {
    if (jwt == null) {
      setPasskeyError(
        new PasskeyError('missing JWT', PasskeyErrorCodes.UNABLE_TO_CONNECT),
      )
      return
    }

    setPasskeyError(null)
    setPasskeyLoading(true)

    /**
     * Retrieves attestation options so clients can enforce unique
     *  non-synchronizing passkeys for each device group
     */
    const [attestationOptsError, attestationOptsResult] = await efwAsync(
      getCreateOptions({
        token: jwt,
        query: { purpose: PASSKEY_PURPOSE, deviceId: deviceId },
      }),
    )

    // Handle remote errors
    if (attestationOptsError != null || attestationOptsResult.data == null) {
      const error = parsePasskeyError({
        message: 'Failed attestation options request',
        apiResult: attestationOptsResult,
        error: attestationOptsError,
      })

      setPasskeyError(error)
      setPasskeyLoading(false)
      return
    }

    // Extract the token and options from the response
    const { token, options } = attestationOptsResult.data

    const [registrationError, registrationResponse] = await efwAsync(
      passkeyUtils.createRawCredential(options),
    )

    // Handles errors from the browser prompt for passkey registration
    if (registrationError != null) {
      const error = parsePasskeyError({
        message: 'Failed to create passkey from browser prompt',
        error: registrationError,
      })

      setPasskeyError(error)
      setPasskeyLoading(false)
      return
    }

    // Add the credential to the users account
    const [addPasskeyError, addPasskeyResult] = await efwAsync(
      addPasskey({
        body: {
          options: token,
          attestation: registrationResponse as AnyObject,
          name: DEFAULT_WEB_WALLET_NAME,
          purpose: PASSKEY_PURPOSE,
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
        message: 'Creation successful, unable to add to database',
        apiResult: addPasskeyResult,
        error: addPasskeyError,
      })

      setPasskeyError(error)
      setPasskeyLoading(false)
      return
    }

    // Set the credentialId for the next step in the process
    setCredentialId(addPasskeyResult.data.credentialId)
    setPasskeyLoading(false)
  }, [jwt, addPasskey, getCreateOptions, deviceId])

  const getSeedPhrase = useCallback(async () => {
    if (jwt == null || (credentialId == null && deviceId == null)) {
      setPhraseError(
        new PasskeyError('missing JWT', PasskeyErrorCodes.UNAUTHORIZED),
      )

      return
    }

    setPhraseLoading(true)
    setPhraseError(null)

    // Get the authentication options for signing the transaction
    const [signOptionsError, signOptionsResult] = await efwAsync(
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
        message: 'Failed to get auth options to read blob',
        apiResult: signOptionsResult,
        error: signOptionsError,
      })

      setPhraseError(error)
      setPhraseLoading(false)
      return
    }

    const [readError, readSeed] = await efwAsync(
      getStoredSeed({
        authenticationOptions: signOptionsResult.data.options,
      }),
    )

    if (readError != null || readSeed == null) {
      const error = parsePasskeyError({
        message: 'Failed to read seed phrase from passkey prompt',
        error: readError,
      })

      setPhraseError(error)
      setPhraseLoading(false)
      return
    }

    const splitPhrase = readSeed.split(' ')
    setPhrase(splitPhrase)
  }, [jwt, credentialId, deviceId, device, backupToken, getSignOptions])

  /**
   * Writes the xpub to the wallet and links it to the passkey,
   * must be called once a credentialId is available from the passkey creation
   * process.
   */
  const createWallet = useCallback(async () => {
    if (jwt == null || credentialId == null || device == null) {
      setWalletError(
        new PasskeyError(
          'Attempted to create wallet before JWT, credentialId, and device are available',
          PasskeyErrorCodes.INCORRECT_STATE,
        ),
      )
      return
    }

    setWalletError(null)
    setWalletLoading(true)

    // Get auth options to WRITE to the passkey largeBlob
    const [authOptionsError, authOptionsResult] = await efwAsync(
      getAuthOptions({
        body: {
          credentialId,
        },
        query: {
          purpose: PASSKEY_PURPOSE,
        },
      }),
    )

    // Handle errors from the server
    if (authOptionsError != null || authOptionsResult.data == null) {
      const error = parsePasskeyError({
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
    const [xPubError, xPubExport] = await efwAsync(
      passkeyDevice.exportXpub({
        hardenedKeyPathPurpose: device.hardenedKeyPathPurpose,
        authenticationOptions: options,
        credentialId,
      }),
    )

    // Handle errors from the passkey prompt
    if (xPubError != null) {
      const error = parsePasskeyError({
        message: 'Failed to export xpub from passkey',
        error: xPubError,
      })

      setWalletError(error)
      setWalletLoading(false)
      return
    }

    setDeviceUpdateLoading(true)

    // Update the device on the server
    const [addWalletError, addWalletResult] = await efwAsync(
      addWallet({
        pathData: {
          deviceId,
        },
        body: {
          xpub: xPubExport.xpub,
          token,
          authenticationResponse:
            xPubExport.authenticationResponse as AnyObject,
          deviceType: DEVICE_TYPE.YUBIKEY,
          blobVersion: xPubExport.blobVersion,
          hardenedKeyPathPurpose: device.hardenedKeyPathPurpose,
        },
        token: jwt,
      }),
    )

    // Handle errors from the server
    if (addWalletError != null || addWalletResult.error != null) {
      const error = parsePasskeyError({
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

    setXPub(xPubExport.xpub)
    setBackupToken(addWalletResult.data?.backupToken)
    setWalletLoading(false)
    return
  }, [credentialId, jwt, deviceId, addWallet, getAuthOptions, device])

  /**
   * Signs the health check message with the passkey, must be called once the xpub
   * is available from the wallet creation process
   */
  const signHealthCheck = useCallback(async () => {
    // Check for required inputs to sign the health check
    if (jwt == null || signature?.key?.walletAccountId == null) {
      setWalletError(
        new PasskeyError(
          'Unable to sign health check without JWT and walletAccountId from signature key',
          PasskeyErrorCodes.INCORRECT_STATE,
        ),
      )
      return
    }

    setSignError(null)
    setSignatureLoading(true)

    // Get the authentication options for signing the health check
    const [authOptionsError, authOptionsResult] = await efwAsync(
      getSignOptions({
        body: {
          signatureId: signature.id,
        },
        token: jwt,
      }),
    )

    // Handle errors from the server
    if (authOptionsError != null || authOptionsResult.data == null) {
      const error = parsePasskeyError({
        message: 'Failed to get auth options to read blob for health check',
        apiResult: authOptionsResult,
        error: authOptionsError,
      })

      setSignError(error)
      setSignatureLoading(false)
      return
    }

    const { options } = authOptionsResult.data

    // Get the wallet account for the signature
    const [walletAccountError, walletAccountResult] = await efwAsync(
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

    // Sign the health check message with the passkey
    const [signatureError, signedMessage] = await efwAsync(
      passkeyDevice.getSignedMessage({
        coin: isEth ? 'ETH' : 'BTC',
        keyPathPurpose: walletAccount.keyPathPurpose,
        keyPathPurposeIsHardened: walletAccount.keyPathPurposeIsHardened,
        keyPathCoinType: walletAccount.keyPathCoinType,
        keyPathAccount: walletAccount.keyPathAccount,
        message: signature.id,
        authenticationOptions: options,
      }),
    )

    // Handle errors from executing the passkey signing
    if (signatureError != null) {
      const error = parsePasskeyError({
        message: 'Failed to sign health check message',
        error: signatureError,
      })

      setSignError(error)
      setSignatureLoading(false)
      return
    }

    // Add the signed message to the server
    const [submissionError, submissionResult] = await efwAsync(
      addSignedMessage({
        body: {
          externalSignatures: [signedMessage],
          deviceType: DEVICE_TYPE.YUBIKEY,
        },
        pathData: { signatureId: signature.id },
        token: jwt,
      }),
    )

    // Handle errors from the server
    if (submissionError != null || submissionResult.data?.signedData == null) {
      const error = parsePasskeyError({
        message: 'Failed to submit signed health check message',
        apiResult: submissionResult,
        error: submissionError,
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
        translateToString('verify_wrong_location_type', {
          actualLocationType: translateToString(
            LOCATION_TYPE_LABEL[actualLocationType],
          ),
          intendedLocationType: translateToString(
            LOCATION_TYPE_LABEL[intendedLocationType],
          ),
        }),
      )
    }

    setSignatureResult(submissionResult.data.signedData)
    setSignatureLoading(false)
  }, [
    jwt,
    getSignOptions,
    addSignedMessage,
    getWalletAccount,
    signature,
    translateToString,
  ])

  const signTransaction = useCallback(async () => {
    // Validate required inputs for signing a transaction
    if (jwt == null || transactionInputs == null) {
      setSignError(
        new PasskeyError(
          'Cannot sign transaction without JWT and transaction inputs',
          PasskeyErrorCodes.INCORRECT_STATE,
        ),
      )
      return
    }

    const { walletAccount, signature, toSign, isTestnet } = transactionInputs

    // Validate required inputs for signing a transaction
    if (walletAccount == null || signature == null || toSign == null) {
      setSignError(
        new PasskeyError(
          'Transaction inputs require walletAccount, signature, and toSign data',
          PasskeyErrorCodes.INCORRECT_STATE,
        ),
      )
      return
    }

    setSignError(null)
    setSignatureLoading(true)

    // Get the authentication options for signing the transaction
    const [authOptionsError, authOptionsResult] = await efwAsync(
      getSignOptions({
        body: {
          signatureId: signature.id,
        },
        token: jwt,
      }),
    )

    // Handle errors from the server
    if (authOptionsError != null || authOptionsResult.data == null) {
      const error = parsePasskeyError({
        message: 'Failed to get auth options to read blob for transaction',
        apiResult: authOptionsResult,
        error: authOptionsError,
      })

      setSignError(error)
      setSignatureLoading(false)
      return
    }

    const signParams = formatSignTxParams({
      selectedDevice: DEVICE_TYPE.YUBIKEY,
      walletAccount,
      signature,
      toSign,
      token: jwt,
      isTestnet,
    })

    // Sign the transaction with the passkey
    const [signatureError, signatures] = await efwAsync(
      passkeyDevice.signTransaction({
        ...signParams,
        device: PASSKEY_DEVICES.YUBIKEY,
        authenticationOptions: authOptionsResult.data.options,
      }),
    )

    // Handle errors from the passkey signing in browser
    if (signatureError != null) {
      const error = parsePasskeyError({
        message: 'Failed to sign transaction with passkey',
        error: signatureError,
      })

      setSignError(error)
      setSignatureLoading(false)
      return
    }

    const [submissionError, submissionResult] = await efwAsync(
      addSignedMessage({
        body: {
          externalSignatures: Array.isArray(signatures)
            ? signatures
            : [signatures],
          deviceType: PASSKEY_DEVICES.YUBIKEY,
        },
        pathData: { signatureId: signature.id },
        token: jwt,
      }),
    )

    if (submissionError != null || submissionResult.data?.signedData == null) {
      const error = parsePasskeyError({
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
        signature,
        addSignatureResult: submissionResult,
      })

    if (showNotification) {
      toast.error(
        translateToString('verify_wrong_location_type', {
          actualLocationType: translateToString(
            LOCATION_TYPE_LABEL[actualLocationType],
          ),
          intendedLocationType: translateToString(
            LOCATION_TYPE_LABEL[intendedLocationType],
          ),
        }),
      )
    }

    setSignatureResult(submissionResult.data.signedData)
    setSignatureLoading(false)
  }, [
    jwt,
    getSignOptions,
    addSignedMessage,
    transactionInputs,
    translateToString,
  ])

  const onConfirmPhrase = useCallback(() => {
    setPhraseConfirmed(true)
  }, [])

  return (
    <WebWalletContext.Provider
      value={{
        xPub,
        signature,
        signatureResult,
        createPasskey,
        createWallet,
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
      }}
    >
      {children}
    </WebWalletContext.Provider>
  )
}

export function useWebWallet(): WebWalletState {
  return useContext(WebWalletContext)
}
