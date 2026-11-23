import {
  AuthenticationResponseJSON,
  Base64URLString,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/types'
import assert from 'assert'

import {
  arrayBufferToBase64String,
  arrayBufferToPlaintext,
  base64StringToArrayBuffer,
  base64ToBase64url,
  base64ToUint8Array,
  base64urlToBase64,
  normalizeBase64OrBase64UrlString,
  stringToArrayBuffer,
} from 'casa-common/src/utils/encodingUtils'

export const PUBLIC_KEY_CREDENTIAL_TYPE = 'public-key' as const
type Base64String = string

export enum PasskeyErrorCodes {
  INVALID_BROWSER = 'INVALID_BROWSER',
  INVALID_DEVICE = 'INVALID_DEVICE',
  INVALID_SUBMISSION = 'INVALID_SUBMISSION',
  INCORRECT_STATE = 'INCORRECT_STATE',
  ALREADY_REGISTERED = 'ALREADY_REGISTERED',
  DUPLICATE = 'DUPLICATE',
  NOT_BACKED_UP = 'NOT_BACKED_UP',
  // The server refused the passkey provider (AAGUID) for this purpose.
  PROVIDER_NOT_ALLOWED = 'PROVIDER_NOT_ALLOWED',
  FAILED_READ = 'UNABLE_TO_READ',
  FAILED_WRITE = 'UNABLE_TO_WRITE',
  USER_EXITED = 'USER_EXITED',
  UNAUTHORIZED = 'UNAUTHORIZED',
  NOT_ALLOWED = 'NOT_ALLOWED',
  UNABLE_TO_CONNECT = 'UNABLE_TO_CONNECT',
  // The server rejected this bundle's request shape; a page reload fixes it.
  OUTDATED_CLIENT = 'OUTDATED_CLIENT',
  UNKNOWN = 'UNKNOWN',
}

/**
 * Specifies the timeout for the navigator.credentials.get() and navigator.credentials.create() methods,
 * which limits the amount of time the user has to respond to the browser prompt before the browser
 * will auto-reject the request.
 *
 * Extends the timeout to 60 seconds to accommodate the time it takes to interact with a yubikey through
 * multiple prompts.
 */
const PROMPT_TIMEOUT_MS = 60000

/**
 * Default WebAuthn user verification requirement used across assertion and attestation paths.
 * Centralised here so the UV policy cannot drift between call sites.
 */
export const DEFAULT_USER_VERIFICATION: UserVerificationRequirement =
  'preferred'

/**
 * Accepts parameters from server-side options requests and re-encodes to accommodate the
 * raw, navigator.credentials.get() method since simplewebauthn does not support largeBlob
 * extensions on passkey authentication requests.
 *
 * The authentication response should be verified by the server before storing the
 * public key to a user's account
 */
export const writeLargeBlob = async ({
  options,
  credentialId,
  blob,
}: {
  options: PublicKeyCredentialRequestOptionsJSON
  credentialId: Base64URLString
  blob: string
}): Promise<{ authenticationResponse: AuthenticationResponseJSON }> => {
  const base64Challenge = base64urlToBase64(options.challenge)
  const bufferChallenge = base64StringToArrayBuffer(base64Challenge)

  const base64Id = normalizeCredentialId(credentialId)
  const bufferId = base64ToUint8Array(base64Id)
  const blobBuffer = stringToArrayBuffer(blob)

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: bufferChallenge,
      allowCredentials: [
        {
          type: PUBLIC_KEY_CREDENTIAL_TYPE,
          id: bufferId,
        },
      ],
      userVerification: options.userVerification ?? DEFAULT_USER_VERIFICATION,
      timeout: PROMPT_TIMEOUT_MS,
      extensions: {
        // @ts-expect-error - navigator credentials do not provide type definitions for largeBlob
        largeBlob: {
          write: blobBuffer,
        },
      },
    },
  })

  const clientExtensionResults = (
    assertion as PublicKeyCredential
  )?.getClientExtensionResults()

  const isLargeBlobWritten = (
    clientExtensionResults as { largeBlob?: { written: boolean } }
  ).largeBlob?.written

  if (isLargeBlobWritten !== true) {
    throw new PasskeyError(
      'Large blob was not written',
      PasskeyErrorCodes.FAILED_WRITE,
    )
  }

  const { rawId } = assertion as PublicKeyCredential
  const response = (assertion as PublicKeyCredential)
    .response as AuthenticatorAssertionResponse

  const base64UrlRawId = arrayBufferToBase64String(rawId)
  const base64UrlId = base64ToBase64url(base64UrlRawId)

  const base64AuthenticatorData = arrayBufferToBase64String(
    response.authenticatorData,
  )
  const base64urlAuthenticatorData = base64ToBase64url(base64AuthenticatorData)

  const base64Signature = arrayBufferToBase64String(response.signature)
  const base64urlSignature = base64ToBase64url(base64Signature)

  const base64clientDataJSON = arrayBufferToBase64String(
    response.clientDataJSON,
  )

  const base64urlClientDataJSON = base64ToBase64url(base64clientDataJSON)

  const authenticationResponse = {
    id: base64UrlId,
    rawId: base64UrlId,
    response: {
      clientDataJSON: base64urlClientDataJSON,
      authenticatorData: base64urlAuthenticatorData,
      signature: base64urlSignature,
    },
    clientExtensionResults,
    type: PUBLIC_KEY_CREDENTIAL_TYPE,
  } as AuthenticationResponseJSON

  return {
    authenticationResponse,
  }
}

/**
 * Accepts parameters from server-side options requests and re-encodes to accommodate the
 * raw, navigator.credentials.get() method since simplewebauthn does not support largeBlob
 * extensions on passkey authentication requests.
 */
export const readLargeBlob = async ({
  options,
}: {
  options: PublicKeyCredentialRequestOptionsJSON
}): Promise<string> => {
  const base64Challenge = base64urlToBase64(options.challenge)
  const bufferChallenge = base64StringToArrayBuffer(base64Challenge)

  const allowCredentials = options.allowCredentials?.map((credential) => {
    const base64Id = normalizeCredentialId(credential.id)
    const bufferId = base64ToUint8Array(base64Id)
    return {
      id: bufferId,
      type: PUBLIC_KEY_CREDENTIAL_TYPE,
    }
  })

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: bufferChallenge,
      allowCredentials,
      userVerification: options.userVerification ?? DEFAULT_USER_VERIFICATION,
      timeout: PROMPT_TIMEOUT_MS,
      extensions: {
        // @ts-expect-error - navigator credentials do not provide type definitions for largeBlob
        largeBlob: {
          read: true,
        },
      },
    },
  })

  const clientExtensionResults = (
    assertion as PublicKeyCredential
  ).getClientExtensionResults()

  // @ts-expect-error - navigator credentials do not provide type support for clientExtensionResults
  if (clientExtensionResults.largeBlob == null) {
    throw new PasskeyError(
      'Unable to read large blob',
      PasskeyErrorCodes.FAILED_READ,
    )
  }

  // @ts-expect-error - navigator credentials do not provide type support for clientExtensionResults
  const largeBlob = clientExtensionResults.largeBlob as { blob?: Buffer }

  if (largeBlob.blob == null) {
    throw new PasskeyError('Large blob empty', PasskeyErrorCodes.FAILED_READ)
  }

  const { blob: blobBuffer } = largeBlob
  const blobString = arrayBufferToPlaintext(blobBuffer)

  if (blobString === '') {
    throw new PasskeyError(
      'Large blob decoded to empty string',
      PasskeyErrorCodes.FAILED_READ,
    )
  }

  return blobString
}

export const PRF_OUTPUT_BYTE_LENGTH = 32

/**
 * Normalizes a WebAuthn PRF extension result to a fresh 32-byte ArrayBuffer.
 *
 * Spec-compliant clients return `prf.results.first` as an ArrayBuffer, but the
 * 1Password browser extension currently returns a plain Array of bytes instead
 * (their bug FS-5593), which SubtleCrypto rejects. Accept both — plus
 * ArrayBuffer views for safety — so PRF-based derivation works the same
 * whether or not 1Password has shipped their fix; the bytes are identical in
 * either container, so the derived key material does not change.
 *
 * Anything else is rejected loudly: PRF output is vault key material, and a
 * mangled container must fail the read rather than derive a plausible-but-wrong
 * key.
 */
export function normalizePrfOutput(prfResult: unknown): ArrayBuffer {
  let bytes: Uint8Array | null = null

  if (prfResult instanceof ArrayBuffer) {
    bytes = new Uint8Array(prfResult)
  } else if (ArrayBuffer.isView(prfResult)) {
    bytes = new Uint8Array(
      prfResult.buffer,
      prfResult.byteOffset,
      prfResult.byteLength,
    )
  } else if (Array.isArray(prfResult)) {
    const isByteArray = prfResult.every(
      (value) =>
        typeof value === 'number' &&
        Number.isInteger(value) &&
        value >= 0 &&
        value <= 255,
    )
    if (isByteArray) {
      bytes = Uint8Array.from(prfResult as number[])
    }
  }

  if (bytes == null || bytes.length !== PRF_OUTPUT_BYTE_LENGTH) {
    throw new PasskeyError(
      `PRF result is not a ${PRF_OUTPUT_BYTE_LENGTH}-byte value`,
      PasskeyErrorCodes.FAILED_READ,
    )
  }

  // Return a fresh copy so callers never hold a view into shared memory.
  return bytes.slice().buffer
}

/**
 * Extract and encode the large blob and PRF results for client side storage, and remove
 * sensitive data from the authentication response before sending to the server.
 */
export function sanitizeAuthenticationResponse(
  authenticationResponse: AuthenticationResponseJSON,
  support?: PasskeySupportOutputs,
): SanitizedAuthenticationResponse {
  // navigator credentials do not provide type support for experimental extension on clientExtensionResults
  const clientExtensionResults =
    authenticationResponse.clientExtensionResults as {
      // `first` is `unknown` because non-compliant clients (1Password's
      // extension) deliver a plain Array here instead of an ArrayBuffer.
      prf?: { results?: { first?: unknown } }
      largeBlob?: { blob?: Buffer }
    }

  const { prf, largeBlob } = clientExtensionResults

  // First, validate that the extension results contain the expected data
  if (support?.hasLargeBlob === true && largeBlob?.blob == null) {
    throw new PasskeyError(
      'Failed to read large blob from large-blob-holding credential',
      PasskeyErrorCodes.FAILED_READ,
    )
  }

  if (support?.prfSupported === true && prf?.results?.first == null) {
    throw new PasskeyError(
      'Failed to read PRF from PRF-holding credential',
      PasskeyErrorCodes.FAILED_WRITE,
    )
  }

  // Next, remove the extension results from the authentication response, as they represent sensitive user key information that must not leave the client
  clientExtensionResults.prf = undefined
  clientExtensionResults.largeBlob = undefined

  assert(
    clientExtensionResults.prf === undefined,
    'clientExtensionResults PRF cannot leak to server',
  )
  assert(
    clientExtensionResults.largeBlob === undefined,
    'clientExtensionResults largeBlob cannot leak to server',
  )

  // Then, return the sanitized authentication response with the cleared-out extension results
  const result: SanitizedAuthenticationResponse = {
    sanitizedAuthenticationResponse: {
      ...authenticationResponse,
      // @ts-expect-error - navigator credentials do not provide type support for clientExtensionResults
      clientExtensionResults,
    },
  }

  // Finally, encode the large blob and PRF results for client side storage
  if (largeBlob?.blob) {
    result.largeBlob = arrayBufferToPlaintext(largeBlob.blob)
  }

  if (prf?.results?.first != null) {
    result.prf = arrayBufferToBase64String(
      normalizePrfOutput(prf.results.first),
    )
  }

  return result
}

/**
 * During passkey credential registration, we always save the credential as a base64-encoded string.
 * However, different client-side libraries may return the credential ID as a base64-encoded string
 * (react-native-passkey), or as a base64url-encoded string (simplewebauthn). This normalization ensures
 * that the credential ID from the client login request can be matched with the credential ID from the
 * database.
 */
export const normalizeCredentialId = (
  // eslint-disable-next-line @typescript-eslint/no-duplicate-type-constituents
  credentialId: Base64String | Base64URLString,
): Base64String => {
  return normalizeBase64OrBase64UrlString(credentialId)
}

export interface PasskeySupportOutputs {
  largeBlobSupported: boolean
  hasLargeBlob: boolean
  prfSupported: boolean
  prfSalt?: Base64String
}

export type ErrorHandler = (error: PasskeyError | Error) => void | Promise<void>

export class PasskeyError extends Error {
  code: PasskeyErrorCodes
  data: unknown
  // Support reference for this failure. The web error parser sets it and logs
  // the same value, so the error screen and Datadog match.
  errorReference?: string

  constructor(message: string, code: PasskeyErrorCodes, data?: unknown) {
    super(message)
    this.code = code
    this.data = data
  }

  /**
   * Return only the error code and message. Error data can contain secrets.
   */
  toString() {
    return `${this.code}: ${this.message}`
  }
}

export function encodeAttestationOptionsToRaw(
  options: PublicKeyCredentialCreationOptionsJSON,
): CredentialCreationOptions {
  return {
    publicKey: {
      ...options,
      challenge: base64ToUint8Array(options.challenge),
      authenticatorSelection: {
        ...options.authenticatorSelection,
        userVerification:
          options.authenticatorSelection?.userVerification ??
          DEFAULT_USER_VERIFICATION,
      },
      excludeCredentials: options.excludeCredentials?.map((credential) => ({
        ...credential,
        id: base64ToUint8Array(credential.id),
      })),
      user: {
        ...options.user,
        id: base64ToUint8Array(options.user.id),
      },
      timeout: PROMPT_TIMEOUT_MS,
    } as CredentialCreationOptions['publicKey'],
  }
}

export function encodeAttestationResponseToVerify(
  registrationResponse: Credential | null,
) {
  if (!registrationResponse) {
    throw new PasskeyError(
      'Invalid registration response',
      PasskeyErrorCodes.USER_EXITED,
    )
  }

  const publicKeyCredential = registrationResponse as PublicKeyCredential
  const rawId = base64ToBase64url(
    arrayBufferToBase64String(publicKeyCredential.rawId),
  )
  const response =
    publicKeyCredential.response as AuthenticatorAttestationResponse
  const clientDataJSON = base64ToBase64url(
    arrayBufferToBase64String(response.clientDataJSON),
  )
  const attestationObject = base64ToBase64url(
    arrayBufferToBase64String(response.attestationObject),
  )
  const clientExtensionResults = publicKeyCredential.getClientExtensionResults()

  return {
    id: rawId,
    rawId,
    response: {
      clientDataJSON,
      attestationObject,
    },
    clientExtensionResults,
    type: publicKeyCredential.type,
  }
}

export async function createRawCredential(
  options: PublicKeyCredentialCreationOptionsJSON,
): Promise<RegistrationResponseJSON> {
  const rawOptions = encodeAttestationOptionsToRaw(options)
  let rawResponse: Credential | null
  try {
    rawResponse = await navigator.credentials.create(rawOptions)
  } catch (error) {
    // WebAuthn signals "this authenticator already holds a credential listed
    // in excludeCredentials" as a DOMException named InvalidStateError (legacy
    // code 11). For Casa that means the chosen provider (e.g. the user's
    // iCloud Keychain) already stores one of the excluded credentials — most
    // often their login passkey, which for security may not share hardware
    // with a signing key. Surface it as ALREADY_REGISTERED so the UI can say
    // so instead of the generic "prompt was dismissed" copy.
    if (error instanceof DOMException && error.name === 'InvalidStateError') {
      throw new PasskeyError(
        'Authenticator already contains an excluded credential',
        PasskeyErrorCodes.ALREADY_REGISTERED,
        { name: error.name, message: error.message },
      )
    }
    throw error
  }
  return encodeAttestationResponseToVerify(
    rawResponse,
  ) as RegistrationResponseJSON
}

export type SanitizedAuthenticationResponse = {
  sanitizedAuthenticationResponse: AuthenticationResponseJSON
  largeBlob?: Base64String
  prf?: Base64String
}
