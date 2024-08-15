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
} from '@casa/common/src/lib/encodingUtils'

export const PUBLIC_KEY_CREDENTIAL_TYPE = 'public-key' as const
type Base64String = string

export enum PasskeyErrorCodes {
  INVALID_BROWSER = 'INVALID_BROWSER',
  INVALID_DEVICE = 'INVALID_DEVICE',
  INVALID_SUBMISSION = 'INVALID_SUBMISSION',
  INCORRECT_STATE = 'INCORRECT_STATE',
  ALREADY_REGISTERED = 'ALREADY_REGISTERED',
  DUPLICATE = 'DUPLICATE',
  FAILED_READ = 'UNABLE_TO_READ',
  FAILED_WRITE = 'UNABLE_TO_WRITE',
  USER_EXITED = 'USER_EXITED',
  UNAUTHORIZED = 'UNAUTHORIZED',
  NOT_ALLOWED = 'NOT_ALLOWED',
  UNABLE_TO_CONNECT = 'UNABLE_TO_CONNECT',
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

/**
 * Extract and encode the large blob and PRF results for client side storage, and remove
 * sensitive data from the authentication response before sending to the server.
 */
export function sanitizeAuthenticationResponse(
  authenticationResponse: AuthenticationResponseJSON,
  support?: PasskeySupportOutputs,
): SanitizedAuthenticationResponse {
  // navigator credentials do not provide type support for experimental extension o clientExtensionResults
  const clientExtensionResults =
    authenticationResponse.clientExtensionResults as {
      prf?: { results?: { first?: Buffer } }
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
    result.prf = arrayBufferToBase64String(prf.results.first)
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

  constructor(message: string, code: PasskeyErrorCodes, data?: unknown) {
    super(message)
    this.code = code
    this.data = data
  }

  /**
   *  Override https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error/toString to include the
   * error code and custom-added data
   */
  toString() {
    const title = `${this.code}: ${this.message}`
    const data = this.data != null ? `-${JSON.stringify(this.data)}` : ''
    return `${title}${data}`
  }
}

export function encodeAttestationOptionsToRaw(
  options: PublicKeyCredentialCreationOptionsJSON,
): CredentialCreationOptions {
  return {
    publicKey: {
      ...options,
      challenge: base64ToUint8Array(options.challenge),
      userVerification: 'discouraged',
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
  const rawResponse = await navigator.credentials.create(rawOptions)
  return encodeAttestationResponseToVerify(
    rawResponse,
  ) as RegistrationResponseJSON
}

export type SanitizedAuthenticationResponse = {
  sanitizedAuthenticationResponse: AuthenticationResponseJSON
  largeBlob?: Base64String
  prf?: Base64String
}
