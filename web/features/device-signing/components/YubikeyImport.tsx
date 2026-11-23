import { deriveXpub } from '@casa/device-signing/src/passkeyDevice'
import { css } from '@emotion/react'
import type { AuthenticationResponseJSON } from '@simplewebauthn/types'
import { useCallback, useEffect, useRef, useState } from 'react'
import CopyToClipboard from 'react-copy-to-clipboard'
import toast from 'react-hot-toast'

import { AnimatedMainContent } from 'src/components/AnimatedContent'
import { SpinningLoader } from 'src/components/Loaders'
import {
  usePasswordVisibility,
  VisibilityToggle,
} from 'src/components/PasswordInputTags'
import SeedPhraseWords, { WordCount } from 'src/components/SeedPhraseWords'
import Spacer from 'src/components/Spacer'
import { RESPONSE_STATUS } from 'src/constants/api'
import COLOR from 'src/constants/color'
import { Device, DEVICE_TYPE } from 'src/constants/device'
import LINK from 'src/constants/link'
import type { Key } from 'src/constants/signature'
import RequireChrome from 'src/features/device-signing/components/RequireChrome'
import {
  InfoCircleIcon,
  PrivacyAlertIcon,
  SuccessCheckIcon,
  WarningAlertIcon,
  YubikeyHeroIcon,
} from 'src/features/device-signing/components/YubikeyImportIcons'
import * as DEVICE_LINKS from 'src/features/device-signing/constants/link'
import { DEVICE_STEPS } from 'src/features/device-signing/constants/steps'
import useDeviceNavigation from 'src/features/device-signing/hooks/useDeviceNavigation'
import useSeedImportSession from 'src/features/device-signing/hooks/useSeedImportSession'
import {
  useWebWallet,
  WebWalletProvider,
  YubiKeyExportData,
} from 'src/features/device-signing/hooks/useWebWallet'
import { validatePasskeyPassphrase } from 'src/features/device-signing/utils/passkeyPassphrase'
import { validateSeedPhrase } from 'src/features/device-signing/utils/seedPhraseValidation'
import useApi from 'src/hooks/useApi'
import useTranslate from 'src/hooks/useTranslate'
import { ReactComponent as InfoIcon } from 'src/images/info-filled-icon.svg'
import type { JsonMap } from 'src/types/Json'

const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000 // 5 minutes

// A passkey signer's seed is always 12 words (v3 derivation).
const PASSKEY_SEED_WORD_COUNT: WordCount = 12
const PASSKEY_WORD_COUNT_OPTIONS: WordCount[] = [PASSKEY_SEED_WORD_COUNT]

const copy = (value: string): string => value

/**
 * Seed-import flow color tokens. Kept in a single block so design refreshes
 * have one place to edit, and so a future migration to the global `COLOR`
 * token enum can do a single import swap rather than chasing hex literals
 * through the file.
 */
const SEED_IMPORT_COLORS = {
  // Primary CTA gradient.
  PURPLE_BUTTON: '#6d20da',
  PURPLE_BUTTON_HOVER: '#5a16b8',
  // Accent link color used inside info-list rows.
  PURPLE_LINK: '#ac7eec',
  PURPLE_LINK_HOVER: '#c2a0f0',
  // Body text used over dark backgrounds.
  TEXT_PRIMARY: '#f1f1f4',
  // Privacy banner background + border.
  YELLOW_BANNER_BG: '#fff7de',
  YELLOW_BANNER_BORDER: '#f7be00',
  // Light purple spinner fill, not in the global COLOR enum.
  SPINNER_LIGHT_PURPLE: '#a29bff',
  // Cyan numbered-step pill, matching the success text color.
  CYAN_STEP_PILL: '#7de2e3',
  // Pure black for text rendered on cyan pills.
  BLACK_ON_LIGHT: '#000000',
  // Translucent card surfaces.
  SURFACE_TRANSLUCENT_6: 'rgba(255, 255, 255, 0.06)',
  SURFACE_TRANSLUCENT_8: 'rgba(255, 255, 255, 0.08)',
  SURFACE_TRANSLUCENT_24: 'rgba(255, 255, 255, 0.24)',
  TEXT_TRANSLUCENT_80: 'rgba(255, 255, 255, 0.8)',
} as const

// Shape returned by PATCH /seedPhraseImportSessions/:id and
// POST /seedPhraseImportSessions/:id/complete. Mirrors the swagger response
// schema declared in routes/seedPhraseImportSessions.ts.
interface SeedImportSessionResponse {
  id: string
  status: string
  expiresAt?: string
}

interface PendingSignatureChallenge extends SeedImportSessionResponse {
  pendingSignatureId: string
  key: Key
}

// Request body for POST /seedPhraseImportSessions/:id/complete. Mirrors the
// `complete` controller's expected shape. Defined locally to give the
// boundary a strong type and avoid the previous `as AnyObject` (yup)
// structural cast through a loose record.
interface CompleteSessionBody {
  token: string
  authenticationResponse: AuthenticationResponseJSON
  blobVersion?: string
}

export default function YubikeyImport({
  device,
  jwt,
  challengeId,
  linkToken,
}: {
  device: Device
  jwt: string
  challengeId: string
  linkToken: string
}) {
  return (
    <WebWalletProvider
      device={device}
      deviceType={DEVICE_TYPE.YUBIKEY}
      jwt={jwt}
    >
      <section
        css={css`
          max-width: 620px;
        `}
      >
        <RequireChrome>
          <YubikeyImportFlow
            device={device}
            jwt={jwt}
            challengeId={challengeId}
            linkToken={linkToken}
          />
        </RequireChrome>
      </section>
    </WebWalletProvider>
  )
}

function YubikeyImportFlow({
  device,
  jwt,
  challengeId,
  linkToken,
}: {
  device: Device
  jwt: string
  challengeId: string
  linkToken: string
}) {
  const {
    step,
    onForward,
    onForwardReady,
    onBackwardReady,
    goingForward,
    goingBackward,
  } = useDeviceNavigation()
  const {
    code,
    status,
    terminal: challengeTerminal,
  } = useSeedImportSession(challengeId, linkToken, jwt)
  const [sessionId, setSessionId] = useState<string | null>(null)
  // Set when the challenge endpoint returns a terminal HTTP status (403/404/410)
  // or when a session-mutating endpoint returns 409 (terminal_state /
  // wrong_status / session_expired). Either way the user can't advance from
  // this tab — surface the session-lost screen instead of leaving them stuck.
  const [sessionTerminal, setSessionTerminal] = useState(false)
  const handleSessionTerminal = useCallback(() => {
    setSessionTerminal(true)
  }, [])
  // Lift the challenge-poll terminal state into the same flag so the
  // session-lost screen renders for both classes of failure.
  useEffect(() => {
    if (challengeTerminal) {
      setSessionTerminal(true)
    }
  }, [challengeTerminal])

  const seedRef = useRef<string | null>(null)
  const passphraseRef = useRef<string | undefined>(undefined)
  const exportDataRef = useRef<YubiKeyExportData | null>(null)
  // Spec Part 4: TRY AGAIN must preserve the word-count selection. The seed
  // entry component re-mounts on retry, so we hold the count in a ref scoped
  // to the parent and pass it back in as initialWordCount. A passkey signer's
  // seed is 12 words only.
  const isPasskeySource = device.deviceType === DEVICE_TYPE.PASSKEY
  const wordCountRef = useRef<WordCount>(
    isPasskeySource ? PASSKEY_SEED_WORD_COUNT : 24,
  )

  // Drives the inactivity-timer arming. Flipped to true in `onSeedReady` once
  // the user has handed the parsed mnemonic up to the flow, and back to false
  // by `clearSeedData`.
  const [hasSeedInMemory, setHasSeedInMemory] = useState(false)

  const clearSeedData = useCallback(() => {
    seedRef.current = null
    passphraseRef.current = undefined
    setHasSeedInMemory(false)
  }, [])

  useEffect(() => () => clearSeedData(), [clearSeedData])

  // Spec Part 11: clear seed state on page navigation, tab close, and bfcache
  // eviction. JS strings cannot be wiped, but dropping references reduces the
  // window during which the mnemonic is reachable. Used in conjunction with
  // the no-store Cache-Control header to prevent the page from being restored
  // from bfcache with the seed still in component state.
  useEffect(() => {
    const cleanup = () => {
      clearSeedData()
    }
    window.addEventListener('beforeunload', cleanup)
    window.addEventListener('pagehide', cleanup)
    return () => {
      window.removeEventListener('beforeunload', cleanup)
      window.removeEventListener('pagehide', cleanup)
    }
  }, [clearSeedData])

  // Session creation derives deviceGroupId + vaultId server-side from deviceId
  // — see POST /seedPhraseImportSessions controller. This avoids a second
  // fetch from the unauthenticated email-link page, where the exportDevice
  // token cannot read GET /deviceGroups/:id.
  const { fetch: createSession } = useApi<{ id: string; expiresAt: string }>({
    serviceName: 'vault',
    method: 'POST',
    path: 'seedPhraseImportSessions',
  })

  const { fetch: cancelSessionRequest } = useApi<{ id: string }>({
    serviceName: 'vault',
    method: 'POST',
    path: 'seedPhraseImportSessions/{id}/cancel',
  })

  // Spec Part 8b: cancel an in-flight session on React unmount when the user
  // navigates away before completion. Frees the partial unique
  // (deviceId, status='active') index slot so the user can restart from
  // mobile without waiting for the 60-minute TTL.
  //
  // We deliberately DON'T cancel on beforeunload/pagehide — the cancel
  // endpoint requires an Authorization header, which navigator.sendBeacon
  // cannot carry, and browsers cancel in-flight fetch() during unload. If
  // the tab actually closes, the server-side TTL handles cleanup.
  //
  // The completion path sets sessionCompletedRef so we don't cancel an
  // already-completed session. The unmount-only cleanup reads from refs
  // so it doesn't re-run on every state change.
  const sessionRefForCancel = useRef<{ id: string | null; jwt: string }>({
    id: null,
    jwt,
  })
  const sessionCompletedRef = useRef(false)
  useEffect(() => {
    sessionRefForCancel.current = { id: sessionId, jwt }
  }, [sessionId, jwt])
  // Mark completion so the unmount cleanup doesn't cancel a finished session.
  useEffect(() => {
    if (step === DEVICE_STEPS.YUBIKEY_IMPORT_SUCCESS) {
      sessionCompletedRef.current = true
    }
  }, [step])
  // Track terminal-state so unmount cleanup doesn't fire a cancel that we
  // already know will 409 (and pollute logs).
  const sessionTerminalRef = useRef(false)
  useEffect(() => {
    sessionTerminalRef.current = sessionTerminal
  }, [sessionTerminal])

  useEffect(() => {
    return () => {
      const { id, jwt: cancelJwt } = sessionRefForCancel.current
      if (
        id != null &&
        !sessionCompletedRef.current &&
        !sessionTerminalRef.current
      ) {
        void cancelSessionRequest({
          pathData: { id },
          token: cancelJwt,
        })
      }
    }
    // Intentionally empty deps — only run on unmount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Inactivity timeout. Spec: "5 minutes of inactivity on any screen with seed
  // in memory triggers session expiry." On fire, we (1) wipe the seed refs,
  // (2) fire-and-forget the server-side cancel so the partial unique index
  // slot is released for restart, and (3) flip the session-terminal flag so
  // the user sees ImportHealthSessionLost instead of a silently emptied form.
  // The activity listeners are only attached while `hasSeedInMemory` is true —
  // pre-seed steps (code display, waiting for mobile approval, passkey setup)
  // hold nothing sensitive, so they should not race the user against the
  // clock.
  //
  // The visibilitychange listener is the backstop for browser timer throttling.
  // Chrome/Firefox aggressively throttle (and after ~5 min hidden, freeze)
  // setTimeout in background tabs, which means a vanilla setTimeout-only
  // implementation can let the seed sit in memory for 10+ wall-clock minutes
  // while the tab is hidden because the scheduled callback simply never
  // fires. `lastActivityRef` records the wall-clock anchor on every reset; on
  // tab restore we compare against Date.now() and expire immediately if the
  // policy window has already elapsed.
  const inactivityTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const lastActivityRef = useRef<number>(Date.now())

  const onInactivityTimeout = useCallback(() => {
    clearSeedData()
    const { id, jwt: cancelJwt } = sessionRefForCancel.current
    if (
      id != null &&
      !sessionCompletedRef.current &&
      !sessionTerminalRef.current
    ) {
      void cancelSessionRequest({
        pathData: { id },
        token: cancelJwt,
      })
    }
    handleSessionTerminal()
  }, [clearSeedData, cancelSessionRequest, handleSessionTerminal])

  const resetInactivityTimer = useCallback(() => {
    lastActivityRef.current = Date.now()
    if (inactivityTimer.current) {
      clearTimeout(inactivityTimer.current)
    }
    inactivityTimer.current = setTimeout(
      onInactivityTimeout,
      INACTIVITY_TIMEOUT_MS,
    )
  }, [onInactivityTimeout])

  // Arm the timer for any step where the user's mnemonic is — or could be —
  // in memory. SEED_ENTRY is included even before Continue is clicked:
  // `ImportSeedEntry` holds typed words in local React state from the first
  // keystroke, so an unsubmitted form on SEED_ENTRY still satisfies "screen
  // with seed in memory" from the spec's perspective. WRITING is included
  // because `seedRef` is populated then. HEALTH is omitted — by the time it
  // renders, `ImportWriting.onComplete` has already cleared the seed refs.
  // `hasSeedInMemory` remains as a defense-in-depth OR branch in case a
  // future change widens the in-memory window past these steps.
  const seedInMemoryRisk =
    hasSeedInMemory ||
    step === DEVICE_STEPS.YUBIKEY_IMPORT_SEED_ENTRY ||
    step === DEVICE_STEPS.YUBIKEY_IMPORT_WRITING

  useEffect(() => {
    if (!seedInMemoryRisk) {
      return
    }
    const handler = () => resetInactivityTimer()
    // `click` and `touchstart` are added alongside the original mousemove +
    // keydown pair because the user may spend long stretches looking at the
    // YubiKey LED, occasionally tapping the screen — pointer-down activity
    // should reset the clock even when the mouse isn't moving.
    window.addEventListener('mousemove', handler)
    window.addEventListener('keydown', handler)
    window.addEventListener('touchstart', handler)
    window.addEventListener('click', handler)
    // Wall-clock backstop for background-tab throttling. If the tab was
    // hidden long enough for the policy window to elapse, expire as soon as
    // the user returns rather than waiting for the (possibly never-firing)
    // setTimeout to wake up.
    const onVisibilityChange = (): void => {
      if (document.visibilityState !== 'visible') {
        return
      }
      const elapsed = Date.now() - lastActivityRef.current
      if (elapsed >= INACTIVITY_TIMEOUT_MS) {
        onInactivityTimeout()
      }
    }
    document.addEventListener('visibilitychange', onVisibilityChange)
    resetInactivityTimer()
    return () => {
      window.removeEventListener('mousemove', handler)
      window.removeEventListener('keydown', handler)
      window.removeEventListener('touchstart', handler)
      window.removeEventListener('click', handler)
      document.removeEventListener('visibilitychange', onVisibilityChange)
      if (inactivityTimer.current) {
        clearTimeout(inactivityTimer.current)
        inactivityTimer.current = null
      }
    }
  }, [seedInMemoryRisk, resetInactivityTimer, onInactivityTimeout])

  // Create the session once the challenge is approved.
  useEffect(() => {
    if (status !== 'approved') {
      return
    }
    if (sessionId != null) {
      return
    }

    let cancelled = false
    void (async () => {
      const result = await createSession({
        body: { deviceId: device.id, challengeId },
        token: jwt,
      })
      if (cancelled) {
        return
      }
      if (result.data?.id != null) {
        setSessionId(result.data.id)
        return
      }
      // Any non-2xx from POST /seedPhraseImportSessions leaves us with no
      // session ID to advance against. Route to the session-lost screen
      // instead of stranding the user on the code display step. The
      // server-side supersede path (see vault-api
      // seedPhraseImportSession.service.ts) means same-user 409s should not
      // reach here in normal operation; what's left is genuine failure (500,
      // network drop, auth-mid-flow, concurrent-create race losing the
      // unique-index lottery, feature flag flipped off) — all unrecoverable
      // from this tab.
      console.error('YubiKey import: createSession failed', {
        status: result.status,
        error: result.error?.message,
      })
      setSessionTerminal(true)
    })()
    return () => {
      cancelled = true
    }
  }, [status, sessionId, device.id, challengeId, jwt, createSession])

  // Spec Part 2: the web app polls the challenge endpoint and advances on its
  // own once the mobile app approves the code — there is no manual "I've
  // entered the code" confirmation on the web side. Once status === 'approved'
  // and the session has been created, advance directly from the code display.
  useEffect(() => {
    if (
      status === 'approved' &&
      sessionId != null &&
      step === DEVICE_STEPS.YUBIKEY_IMPORT_CODE_DISPLAY
    ) {
      void onForward(DEVICE_STEPS.YUBIKEY_IMPORT_PASSKEY)
    }
  }, [status, sessionId, step, onForward])

  // The step-switch content has to live inside AnimatedMainContent so that
  // calling onForward(nextStep) drives the framer-motion exit animation,
  // which fires onExitComplete → onForwardReady → setStep. Without this
  // wrapper, onForward sets `goingForward` in the recoil atom but nothing
  // ever fires the readiness callback, so `step` never advances and the
  // user gets stuck on the code-display screen even after polling reports
  // approved and the session is created. See DeviceConfirmation for the
  // canonical pattern.
  const stepContent = (() => {
    // Success is the only true terminal-success state for this flow. Once
    // we land here, no late-arriving 409/403 (or any other failure signal)
    // should override the success UI — the import already succeeded server-
    // side and the user just needs to close the tab.
    if (step === DEVICE_STEPS.YUBIKEY_IMPORT_SUCCESS) {
      return <ImportSuccess />
    }
    if (sessionTerminal) {
      return <ImportHealthSessionLost />
    }
    switch (step) {
      case DEVICE_STEPS.YUBIKEY_IMPORT_CODE_DISPLAY:
        return <ImportCodeDisplay code={code} linkToken={linkToken} />
      case DEVICE_STEPS.YUBIKEY_IMPORT_WAITING:
        return <ImportWaiting />
      case DEVICE_STEPS.YUBIKEY_IMPORT_PASSKEY:
        return (
          <ImportPasskeySetup
            sessionId={sessionId}
            jwt={jwt}
            onSessionTerminal={handleSessionTerminal}
          />
        )
      case DEVICE_STEPS.YUBIKEY_IMPORT_SEED_ENTRY:
        return (
          <ImportSeedEntry
            device={device}
            initialWordCount={wordCountRef.current}
            onWordCountChange={(count) => {
              wordCountRef.current = count
            }}
            onSeedReady={(seed, pass) => {
              seedRef.current = seed
              passphraseRef.current = pass
              setHasSeedInMemory(true)
            }}
          />
        )
      case DEVICE_STEPS.YUBIKEY_IMPORT_WRITING:
        return (
          <ImportWriting
            sessionId={sessionId}
            jwt={jwt}
            getSeed={() => seedRef.current}
            getPassphrase={() => passphraseRef.current}
            onSessionTerminal={handleSessionTerminal}
            onComplete={(data) => {
              exportDataRef.current = data
              clearSeedData()
            }}
          />
        )
      case DEVICE_STEPS.YUBIKEY_IMPORT_HEALTH:
        return (
          <ImportHealth
            jwt={jwt}
            sessionId={sessionId}
            getExportData={() => exportDataRef.current}
          />
        )
      default:
        return <ImportCodeDisplay code={code} linkToken={linkToken} />
    }
  })()

  return (
    <AnimatedMainContent
      visible={goingForward == null && goingBackward == null}
      onExitComplete={() => {
        if (goingForward == null) {
          onBackwardReady()
        } else {
          onForwardReady()
        }
      }}
    >
      {stepContent}
    </AnimatedMainContent>
  )
}

function ImportCodeDisplay({
  code,
  linkToken,
}: {
  code: string | null
  linkToken: string
}) {
  const digits = (code ?? '------').split('')

  return (
    <div
      css={css`
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 62px;
        width: 540px;
        margin: 0 auto;
      `}
    >
      <div
        css={css`
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 45px;
          width: 100%;
        `}
      >
        <p
          css={css`
            font-family: 'Maison Neue', sans-serif;
            font-weight: 600;
            font-size: 20px;
            line-height: 28px;
            letter-spacing: 0.1px;
            color: ${COLOR.WHITE};
            text-align: center;
            margin: 0;
            width: 552px;
            word-break: break-word;
          `}
        >
          {copy(
            'Before continuing, please enter this 6-digit code into the screen on your mobile app:',
          )}
        </p>
        <div
          data-testid='seed-import-verification-code'
          css={css`
            background: ${SEED_IMPORT_COLORS.SURFACE_TRANSLUCENT_6};
            border-radius: 8px;
            width: 388px;
            height: 68px;
            padding: 10px;
            box-sizing: border-box;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 24px;
            font-family: 'Maison Neue', sans-serif;
            font-weight: 500;
            font-size: 36px;
            line-height: 44px;
            letter-spacing: 0;
            color: ${SEED_IMPORT_COLORS.TEXT_PRIMARY};
            text-align: center;
            white-space: nowrap;
          `}
        >
          {digits.map((digit, idx) => (
            // eslint-disable-next-line react/no-array-index-key
            <span key={idx}>{digit}</span>
          ))}
        </div>
      </div>
      <ImportantInfoBox linkToken={linkToken} />
    </div>
  )
}

function buildIncognitoCopyUrl(linkToken: string): string {
  const url = new URL(window.location.href)
  if (linkToken !== '') {
    url.searchParams.set('linkToken', linkToken)
  }
  return url.toString()
}

function ImportantInfoBox({
  linkToken,
}: {
  linkToken: string
}): React.ReactElement {
  const { translate } = useTranslate()
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (copied) {
      toast.success('Copied')
      const timer = setTimeout(() => setCopied(false), 5000)
      return () => clearTimeout(timer)
    }
  }, [copied])

  return (
    <div
      css={css`
        background: ${SEED_IMPORT_COLORS.SURFACE_TRANSLUCENT_6};
        border-radius: 12px;
        padding: 16px;
        width: 100%;
        display: flex;
        flex-direction: column;
        gap: 16px;
        align-items: flex-start;
      `}
    >
      <p
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-weight: 700;
          font-size: 14px;
          line-height: 1.5;
          color: ${COLOR.WHITE};
          margin: 0;
          white-space: nowrap;
        `}
      >
        {copy('Important')}
      </p>
      <div
        css={css`
          display: flex;
          gap: 8px;
          align-items: flex-start;
          width: 100%;
        `}
      >
        <div
          css={css`
            display: flex;
            align-items: flex-start;
            padding-top: 2px;
            flex-shrink: 0;
          `}
        >
          <InfoCircleIcon />
        </div>
        <p
          css={css`
            flex: 1 0 0;
            min-width: 0;
            font-family: 'Maison Neue', sans-serif;
            font-weight: 500;
            font-size: 14px;
            line-height: 1.5;
            color: ${COLOR.WHITE};
            margin: 0;
            word-break: break-word;
          `}
        >
          {translate('yubikey_import_closed_screen_tip')}
        </p>
      </div>
      <div
        css={css`
          display: flex;
          gap: 8px;
          align-items: flex-start;
          width: 100%;
        `}
      >
        <div
          css={css`
            display: flex;
            align-items: flex-start;
            padding-top: 2px;
            flex-shrink: 0;
          `}
        >
          <InfoCircleIcon />
        </div>
        <p
          css={css`
            flex: 1 0 0;
            min-width: 0;
            font-family: 'Maison Neue', sans-serif;
            font-weight: 500;
            font-size: 14px;
            line-height: 1.5;
            color: ${COLOR.WHITE};
            margin: 0;
            word-break: break-word;
          `}
        >
          {translate('yubikey_import_incognito_tip')}{' '}
          <CopyToClipboard
            text={buildIncognitoCopyUrl(linkToken)}
            onCopy={() => {
              if (!copied) {
                setCopied(true)
              }
            }}
          >
            <InlineLink as='button' type='button'>
              {translate('yubikey_copy_link')}
            </InlineLink>
          </CopyToClipboard>
        </p>
      </div>
    </div>
  )
}

function ImportWaiting() {
  return (
    <div
      css={css`
        text-align: center;
      `}
    >
      <SpinningLoader onDark={true} size={48} />
      <Spacer unit={6} />
      <p
        css={css`
          font-size: 16px;
          color: ${COLOR.GRAY_200};
        `}
      >
        {copy('Waiting for you to approve the code in your Casa app…')}
      </p>
    </div>
  )
}

function ImportPasskeySetup({
  sessionId,
  jwt,
  onSessionTerminal,
}: {
  sessionId: string | null
  jwt: string
  onSessionTerminal: () => void
}) {
  const { onForward } = useDeviceNavigation()
  const { createPasskey, passkeyLoading, passkeyError } = useWebWallet()

  const { fetch: patchSession } = useApi<SeedImportSessionResponse>({
    serviceName: 'vault',
    method: 'PATCH',
    path: 'seedPhraseImportSessions/{id}',
  })

  // Use the returned credentialId from createPasskey instead of reading it
  // from the closure — see useWebWallet for why. Without this, the click
  // handler's closure captured a stale (null) credentialId and the post-
  // ceremony early-return forced the user to run the YubiKey WebAuthn
  // ceremony twice before the flow advanced.
  const handleSetup = useCallback(async () => {
    const newCredentialId = await createPasskey()
    if (newCredentialId == null || newCredentialId === '') {
      return
    }
    if (sessionId == null) {
      return
    }

    const patchResult = await patchSession({
      pathData: { id: sessionId },
      body: { passkeyCredentialId: newCredentialId },
      token: jwt,
    })
    if (patchResult.error != null) {
      // 409 = session in terminal_state / wrong_status / expired. The session
      // can't be advanced from here — route to the session-lost screen rather
      // than leaving the user stuck on this step.
      if (patchResult.status === RESPONSE_STATUS.CONFLICT) {
        onSessionTerminal()
      }
      return
    }

    void onForward(DEVICE_STEPS.YUBIKEY_IMPORT_SEED_ENTRY)
  }, [
    createPasskey,
    sessionId,
    patchSession,
    jwt,
    onForward,
    onSessionTerminal,
  ])

  return (
    <div
      css={css`
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 40px;
        width: 100%;
        max-width: 560px;
        margin: 0 auto;
      `}
    >
      <div
        css={css`
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 45px;
          width: 540px;
          max-width: 100%;
        `}
      >
        <div
          css={css`
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 16px;
          `}
        >
          <YubikeyHeroIcon />
          <h1
            css={css`
              font-family: 'Maison Neue', sans-serif;
              font-weight: 700;
              font-size: 36px;
              line-height: 1.25;
              letter-spacing: 0;
              color: ${COLOR.WHITE};
              text-align: center;
              margin: 0;
              max-width: 532px;
              word-break: break-word;
            `}
          >
            {copy('Plug in your YubiKey')}
          </h1>
          <p
            css={css`
              font-family: 'Maison Neue', sans-serif;
              font-weight: 400;
              font-size: 24px;
              line-height: 1.5;
              letter-spacing: 0;
              color: ${COLOR.WHITE};
              text-align: center;
              margin: 0;
              max-width: 540px;
              word-break: break-word;
            `}
          >
            {copy('Once your YubiKey is plugged in, please continue.')}
          </p>
        </div>
        <ContinueButton
          onClick={() => void handleSetup()}
          disabled={passkeyLoading}
          loading={passkeyLoading}
          testId='yubikey-import-passkey-continue'
        />
      </div>
      {passkeyError && (
        <p
          css={css`
            font-family: 'Maison Neue', sans-serif;
            color: ${COLOR.RED_500};
            font-size: 14px;
            margin: 0;
            text-align: center;
          `}
        >
          {copy('Failed to set up YubiKey passkey. Please try again.')}
        </p>
      )}
      <ImportantInfoListBox />
    </div>
  )
}

/**
 * Purple uppercase pill CTA. Width, color, and typography all diverge from
 * DefaultButton, so keep this local to avoid forking the shared component.
 * Reused for "FINISH SETUP" on the Almost-Done step, parameterized via `label`.
 */
function ContinueButton({
  onClick,
  disabled,
  loading,
  label = 'Continue',
  testId,
}: {
  onClick: () => void
  disabled: boolean
  loading: boolean
  label?: string
  testId?: string
}): React.ReactElement {
  return (
    <button
      type='button'
      onClick={onClick}
      disabled={disabled}
      data-testid={testId}
      css={css`
        background: ${SEED_IMPORT_COLORS.PURPLE_BUTTON};
        border: none;
        border-radius: 128px;
        width: 350px;
        max-width: 100%;
        padding: 16px 24px;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        color: ${SEED_IMPORT_COLORS.TEXT_PRIMARY};
        font-family: 'Maison Neue', sans-serif;
        font-weight: 600;
        font-size: 14px;
        line-height: 24px;
        letter-spacing: 0.35px;
        text-transform: uppercase;
        cursor: ${disabled ? 'not-allowed' : 'pointer'};
        opacity: ${disabled && !loading ? 0.6 : 1};

        &:hover:not(:disabled) {
          background: ${SEED_IMPORT_COLORS.PURPLE_BUTTON_HOVER};
        }
      `}
    >
      {loading ? <SpinningLoader onDark={true} size={20} /> : label}
    </button>
  )
}

/**
 * Three bulleted info rows inside a translucent card. The firmware row includes a
 * purple inline link. Keeps the existing inline InfoCircleIcon for visual
 * consistency with the code-display screen.
 */
function ImportantInfoListBox(): React.ReactElement {
  return (
    <div
      css={css`
        background: ${SEED_IMPORT_COLORS.SURFACE_TRANSLUCENT_6};
        border-radius: 12px;
        padding: 16px;
        display: flex;
        flex-direction: column;
        gap: 16px;
        align-items: flex-start;
        width: 100%;
        max-width: 560px;
        box-sizing: border-box;
      `}
    >
      <p
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-weight: 700;
          font-size: 14px;
          line-height: 1.5;
          color: ${COLOR.WHITE};
          margin: 0;
        `}
      >
        {copy('Important')}
      </p>
      <InfoRow>
        {copy(
          "Before proceeding, make sure this YubiKey isn't already assigned as your 2FA method or used as another key in this vault.",
        )}
      </InfoRow>
      <InfoRow>
        {copy(
          'If the firmware on your YubiKey is older than 5.5, you will need to use a newer one.',
        )}{' '}
        <InlineLink
          href={DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_FIRMWARE}
          target='_blank'
          rel='noopener noreferrer'
        >
          {copy('Learn how to check.')}
        </InlineLink>
      </InfoRow>
    </div>
  )
}

function InfoRow({
  children,
}: {
  children: React.ReactNode
}): React.ReactElement {
  return (
    <div
      css={css`
        display: flex;
        gap: 8px;
        align-items: flex-start;
        width: 100%;
      `}
    >
      <div
        css={css`
          display: flex;
          align-items: flex-start;
          padding-top: 2px;
          flex-shrink: 0;
        `}
      >
        <InfoCircleIcon />
      </div>
      <p
        css={css`
          flex: 1 0 0;
          min-width: 0;
          font-family: 'Maison Neue', sans-serif;
          font-weight: 500;
          font-size: 14px;
          line-height: 1.5;
          color: ${COLOR.WHITE};
          margin: 0;
          word-break: break-word;
        `}
      >
        {children}
      </p>
    </div>
  )
}

/**
 * Inline accent link used inside ImportantInfoListBox for the "Learn how to check."
 * anchor. Also accepts `as='button'` to render a visually identical button (no href)
 * for any future inline action.
 */
function InlineLink({
  as,
  children,
  ...rest
}: {
  as?: 'button'
  children: React.ReactNode
  href?: string
  target?: string
  rel?: string
  type?: 'button'
  onClick?: () => void
}): React.ReactElement {
  const sharedCss = css`
    font-family: 'Maison Neue', sans-serif;
    font-weight: 700;
    font-size: 14px;
    line-height: 1.5;
    color: ${SEED_IMPORT_COLORS.PURPLE_LINK};
    background: none;
    border: none;
    padding: 0;
    cursor: pointer;
    text-decoration: none;

    &:hover {
      color: ${SEED_IMPORT_COLORS.PURPLE_LINK_HOVER};
    }
  `

  if (as === 'button') {
    return (
      <button css={sharedCss} {...rest}>
        {children}
      </button>
    )
  }
  return (
    <a css={sharedCss} {...rest}>
      {children}
    </a>
  )
}

function ImportSeedEntry({
  device,
  onSeedReady,
  initialWordCount,
  onWordCountChange,
}: {
  device: Device
  onSeedReady: (seed: string, passphrase: string | undefined) => void
  initialWordCount: WordCount
  onWordCountChange: (count: WordCount) => void
}) {
  const { onForward } = useDeviceNavigation()
  // Moving a passkey signer to a YubiKey: vault-api generated the seed as 12
  // words and the passphrase as 8 BIP-39 words joined by one space. The
  // passphrase is mandatory and must match that form exactly, or the derived
  // xpub differs.
  const isPasskeySource = device.deviceType === DEVICE_TYPE.PASSKEY

  const [wordCount, setWordCount] = useState<WordCount>(initialWordCount)
  const [words, setWords] = useState<string[]>(() =>
    Array(initialWordCount).fill(''),
  )
  const [usePassphrase, setUsePassphrase] = useState(isPasskeySource)
  const [passphrase, setPassphrase] = useState('')
  const [hasSubmitted, setHasSubmitted] = useState(false)
  const [validationError, setValidationError] = useState<string | null>(null)
  const [suspectPositions, setSuspectPositions] = useState<number[]>([])

  const handleWordCountChange = useCallback(
    (next: WordCount) => {
      // The paste auto-adjust in SeedPhraseWords can ask for any count.
      if (isPasskeySource && next !== PASSKEY_SEED_WORD_COUNT) {
        return
      }
      setWordCount(next)
      onWordCountChange(next)
      setWords((prev) => {
        const out = Array(next).fill('')
        for (let i = 0; i < Math.min(prev.length, next); i++) {
          out[i] = prev[i]
        }
        return out
      })
    },
    [isPasskeySource, onWordCountChange],
  )

  const handleWordsChange = useCallback((next: string[]) => {
    setWords(next)
    setValidationError(null)
    setSuspectPositions([])
  }, [])

  // Continue is only enabled once every word slot is non-empty. Submit-time
  // validation handles BIP-39 dictionary + checksum + suspect-position
  // highlighting.
  const allFilled = words.length === wordCount && words.every((w) => w !== '')
  const canContinue = allFilled && (!usePassphrase || passphrase !== '')

  const handleContinue = useCallback(() => {
    setHasSubmitted(true)
    const result = validateSeedPhrase(words, wordCount)
    if (result.error != null) {
      setValidationError(result.error)
      setSuspectPositions(result.suspectPositions)
      return
    }
    setSuspectPositions([])
    const phrase = words.join(' ')
    let pass: string | undefined
    if (isPasskeySource) {
      const checked = validatePasskeyPassphrase(passphrase)
      if (!checked.ok) {
        setValidationError(checked.error)
        return
      }
      pass = checked.passphrase
    } else {
      pass = usePassphrase && passphrase !== '' ? passphrase : undefined
    }

    if (device.xpub == null) {
      setValidationError('Device has no xpub on record. Cannot validate.')
      return
    }

    const derivedXpub = deriveXpub(phrase, pass, device.hardenedKeyPathPurpose)
    if (derivedXpub !== device.xpub) {
      // A passkey source always has a passphrase, so point at word entry and
      // spacing. Other sources get a hint that depends on whether the user
      // opted in to a passphrase.
      if (isPasskeySource) {
        setValidationError(
          'This seed phrase or passphrase does not match this key. Check each word, and put one space between each passphrase word.',
        )
      } else {
        setValidationError(
          pass != null
            ? 'This seed phrase does not match this key. This can happen if the passphrase is incorrect or if the key was originally created without a passphrase.'
            : 'This seed phrase does not match this key. If you set up the seed with a passphrase, enable the passphrase option and try again.',
        )
      }
      return
    }

    setValidationError(null)
    onSeedReady(phrase, pass)
    void onForward(DEVICE_STEPS.YUBIKEY_IMPORT_WRITING)
  }, [
    words,
    wordCount,
    isPasskeySource,
    usePassphrase,
    passphrase,
    device,
    onSeedReady,
    onForward,
  ])

  return (
    <div
      css={css`
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 32px;
        width: 100%;
        max-width: 560px;
        margin: 0 auto;
      `}
    >
      <div
        css={css`
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 16px;
          width: 100%;
        `}
      >
        <h1
          css={css`
            font-family: 'Maison Neue', sans-serif;
            font-weight: 700;
            font-size: 36px;
            line-height: 1.25;
            color: ${COLOR.WHITE};
            text-align: center;
            margin: 0;
          `}
        >
          {copy('YubiKey ready.')}
        </h1>
        <p
          css={css`
            font-family: 'Maison Neue', sans-serif;
            font-weight: 400;
            font-size: 18px;
            line-height: 28px;
            color: ${SEED_IMPORT_COLORS.TEXT_PRIMARY};
            text-align: center;
            margin: 0;
          `}
        >
          {isPasskeySource
            ? copy('Enter your Seed Phrase (12 words) in all lower case')
            : copy('Enter your Seed Phrase (12-24 words) in all lower case')}
        </p>
        <PrivacyAlert />
      </div>

      <SeedPhraseWords
        input={true}
        words={words}
        wordCount={wordCount}
        onWordsChange={handleWordsChange}
        onWordCountChange={handleWordCountChange}
        suspectPositions={suspectPositions}
        hasSubmitted={hasSubmitted}
        wordCountOptions={
          isPasskeySource ? PASSKEY_WORD_COUNT_OPTIONS : undefined
        }
      />

      <PassphraseCheckbox
        checked={usePassphrase}
        required={isPasskeySource}
        helperText={
          isPasskeySource
            ? copy(
                'Enter the 8 passphrase words in order. Put one space between each word.',
              )
            : undefined
        }
        onChange={(next) => {
          setUsePassphrase(next)
          if (!next) {
            setPassphrase('')
          }
        }}
        passphrase={passphrase}
        onPassphraseChange={setPassphrase}
      />

      {validationError != null && validationError !== '' && (
        <div
          css={css`
            display: flex;
            gap: 12px;
            align-items: center;
            justify-content: center;
            padding: 2px 0;
          `}
        >
          <InfoIcon
            css={css`
              width: 12px;
              height: 12px;
              flex-shrink: 0;
              path {
                fill: ${COLOR.PINK_500};
              }
            `}
          />
          <p
            css={css`
              font-family: 'Maison Neue', sans-serif;
              font-weight: 500;
              font-size: 12px;
              line-height: 1.5;
              color: ${COLOR.PINK_500};
              margin: 0;
              word-break: break-word;
            `}
          >
            {validationError}
          </p>
        </div>
      )}

      <ContinueButton
        onClick={handleContinue}
        disabled={!canContinue}
        loading={false}
        testId='seed-import-seed-continue'
      />
    </div>
  )
}

/**
 * Yellow privacy banner. Distinct enough from the existing Banner component's
 * `warning` variant that we render it inline here rather than forking the
 * shared component.
 */
function PrivacyAlert(): React.ReactElement {
  return (
    <div
      css={css`
        background: ${SEED_IMPORT_COLORS.YELLOW_BANNER_BG};
        border: 1px solid ${SEED_IMPORT_COLORS.YELLOW_BANNER_BORDER};
        border-radius: 8px;
        padding: 12px;
        display: flex;
        gap: 12px;
        align-items: flex-start;
        width: 100%;
      `}
    >
      <div
        css={css`
          flex-shrink: 0;
          padding-top: 2px;
        `}
      >
        <PrivacyAlertIcon />
      </div>
      <p
        css={css`
          flex: 1 0 0;
          min-width: 0;
          font-family: 'Maison Neue', sans-serif;
          font-size: 14px;
          line-height: 1.5;
          color: #000;
          margin: 0;
        `}
      >
        <span
          css={css`
            font-weight: 700;
          `}
        >
          {copy("Make sure you're in a private location")}
        </span>{' '}
        {copy('where nobody else can view your screen or your seed phrase.')}
      </p>
    </div>
  )
}

function PassphraseCheckbox({
  checked,
  required = false,
  helperText,
  onChange,
  passphrase,
  onPassphraseChange,
}: {
  checked: boolean
  /** The passphrase must be entered: the checkbox is locked on. */
  required?: boolean
  /** Guidance shown under the passphrase input. */
  helperText?: string
  onChange: (next: boolean) => void
  passphrase: string
  onPassphraseChange: (next: string) => void
}): React.ReactElement {
  const { inputType, onToggle } = usePasswordVisibility()

  // A single-line input drops line breaks from pasted text, which would run
  // words together ("ability\nable" -> "abilityable"). For the required
  // passkey passphrase, paste each whitespace run as one space instead.
  const handleRequiredPaste = (
    e: React.ClipboardEvent<HTMLInputElement>,
  ): void => {
    const text = e.clipboardData.getData('text')
    e.preventDefault()
    const input = e.currentTarget
    const start = input.selectionStart ?? passphrase.length
    const end = input.selectionEnd ?? passphrase.length
    onPassphraseChange(
      passphrase.slice(0, start) +
        text.replace(/\s+/g, ' ') +
        passphrase.slice(end),
    )
  }

  return (
    <div
      css={css`
        width: 100%;
        max-width: 526px;
        display: flex;
        flex-direction: column;
        gap: 8px;
      `}
    >
      <label
        css={css`
          display: flex;
          gap: 12px;
          align-items: flex-start;
          cursor: ${required ? 'default' : 'pointer'};
        `}
      >
        <input
          type='checkbox'
          checked={required || checked}
          disabled={required}
          onChange={(e) => onChange(e.target.checked)}
          data-testid='seed-input-use-passphrase'
          css={css`
            margin: 2px 0 0;
            cursor: ${required ? 'default' : 'pointer'};
          `}
        />
        <div
          css={css`
            display: flex;
            flex-direction: column;
            gap: 4px;
          `}
        >
          <span
            css={css`
              font-family: 'Maison Neue', sans-serif;
              font-weight: 600;
              font-size: 14px;
              line-height: 16px;
              color: ${SEED_IMPORT_COLORS.TEXT_PRIMARY};
            `}
          >
            {copy('My seed phrase includes a Passphrase.')}
          </span>
          <span
            css={css`
              font-family: 'Maison Neue', sans-serif;
              font-weight: 400;
              font-size: 14px;
              line-height: 20px;
              color: ${SEED_IMPORT_COLORS.TEXT_PRIMARY};
            `}
          >
            {required
              ? copy(
                  'Your passkey signer uses an 8-word passphrase. You must enter it.',
                )
              : copy(
                  'An optional extra word some people added during device setup.',
                )}
          </span>
        </div>
      </label>
      {(required || checked) && (
        <div
          css={css`
            position: relative;
            margin-left: 28px;
            display: flex;
            align-items: center;
          `}
        >
          <input
            type={inputType}
            value={passphrase}
            onChange={(e) => onPassphraseChange(e.target.value)}
            onPaste={required ? handleRequiredPaste : undefined}
            placeholder={
              required
                ? 'word word word word word word word word'
                : 'Passphrase'
            }
            autoComplete='off'
            spellCheck={false}
            data-lpignore='true'
            data-gramm='false'
            data-testid='seed-input-passphrase'
            css={css`
              flex: 1;
              padding: 10px 40px 10px 12px;
              border-radius: 8px;
              border: 1px solid ${SEED_IMPORT_COLORS.SURFACE_TRANSLUCENT_24};
              background: ${SEED_IMPORT_COLORS.SURFACE_TRANSLUCENT_6};
              color: ${COLOR.WHITE};
              font-family: 'Maison Neue', sans-serif;
              font-size: 14px;
              outline: none;
              &:focus {
                border-color: ${COLOR.PERIWINKLE_01};
              }
            `}
          />
          <span
            css={css`
              position: absolute;
              right: 12px;
              top: 50%;
              transform: translateY(-50%);
              display: flex;
              align-items: center;
            `}
          >
            <VisibilityToggle onToggle={onToggle} inputType={inputType} />
          </span>
        </div>
      )}
      {(required || checked) && helperText != null && (
        <p
          data-testid='seed-input-passphrase-helper'
          css={css`
            margin: 0 0 0 28px;
            font-family: 'Maison Neue', sans-serif;
            font-weight: 400;
            font-size: 12px;
            line-height: 1.5;
            color: ${SEED_IMPORT_COLORS.TEXT_TRANSLUCENT_80};
          `}
        >
          {helperText}
        </p>
      )}
    </div>
  )
}

function ImportWriting({
  sessionId,
  jwt,
  getSeed,
  getPassphrase,
  onSessionTerminal,
  onComplete,
}: {
  sessionId: string | null
  jwt: string
  getSeed: () => string | null
  getPassphrase: () => string | undefined
  onSessionTerminal: () => void
  onComplete: (data: YubiKeyExportData) => void
}) {
  const { onForward } = useDeviceNavigation()
  const { writeSeedToYubiKey, walletError } = useWebWallet()
  const [status, setStatus] = useState<'idle' | 'loading' | 'error'>('idle')
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const hasAutoStartedRef = useRef(false)

  const { fetch: patchSession } = useApi<SeedImportSessionResponse>({
    serviceName: 'vault',
    method: 'PATCH',
    path: 'seedPhraseImportSessions/{id}',
  })

  const write = useCallback(async () => {
    const seed = getSeed()
    const passphrase = getPassphrase()

    if (seed == null || seed === '') {
      setErrorMessage(
        'Seed phrase data was cleared. Please restart the import flow.',
      )
      setStatus('error')
      return
    }

    setStatus('loading')

    const exportData = await writeSeedToYubiKey(seed, passphrase)

    if (exportData == null || walletError) {
      setErrorMessage(
        'YubiKey setup failed. Make sure your YubiKey is connected and try again.',
      )
      setStatus('error')
      return
    }

    if (sessionId != null) {
      const patchResult = await patchSession({
        pathData: { id: sessionId },
        body: { blobWritten: true },
        token: jwt,
      })
      if (patchResult.error != null) {
        if (patchResult.status === RESPONSE_STATUS.CONFLICT) {
          onSessionTerminal()
          return
        }
        setErrorMessage('Failed to record blob write. Please try again.')
        setStatus('error')
        return
      }
    }

    onComplete(exportData)
    void onForward(DEVICE_STEPS.YUBIKEY_IMPORT_HEALTH)
  }, [
    sessionId,
    jwt,
    getSeed,
    getPassphrase,
    writeSeedToYubiKey,
    walletError,
    patchSession,
    onSessionTerminal,
    onComplete,
    onForward,
  ])

  useEffect(() => {
    if (hasAutoStartedRef.current) {
      return
    }
    hasAutoStartedRef.current = true
    void write()
  }, [write])

  if (status === 'error') {
    if (errorMessage != null) {
      // Preserve diagnostic detail in the console even though the user-facing
      // screen uses the shared generic copy. Matches the logging pattern in
      // ImportHealth (line 1722 area).
      console.error('YubiKey import write failed:', errorMessage)
    }
    return (
      <ImportHealthError
        onTryAgain={() => void write()}
        onStartOver={() => window.location.reload()}
      />
    )
  }

  return (
    <div
      css={css`
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 45px;
        width: 100%;
        max-width: 540px;
        margin: 0 auto;
      `}
    >
      <div
        css={css`
          /* Match ImportHealthLoading spinner styling — same light purple
             override used across all "passkey popup pending" screens in this
             flow. */
          svg path {
            fill: ${SEED_IMPORT_COLORS.SPINNER_LIGHT_PURPLE};
          }
        `}
      >
        <SpinningLoader onDark={true} size={45} />
      </div>
      <p
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-weight: 400;
          font-size: 24px;
          line-height: 1.5;
          color: ${COLOR.WHITE};
          text-align: center;
          margin: 0;
          width: 100%;
          word-break: break-word;
        `}
      >
        {copy(
          'Please follow the steps in the passkey popup to set up your YubiKey.',
        )}
      </p>
      <ImportantNoteCard
        rows={[
          {
            text: (
              <>
                {copy(
                  'If you’re using a password manager, it might pop open first. Please close it.',
                )}
              </>
            ),
          },
          {
            text: (
              <>
                {copy(
                  'If you haven’t set up a PIN on your YubiKey, you’ll be prompted to create one. This is required for setup.',
                )}
              </>
            ),
          },
          {
            hideIcon: true,
            text: (
              <>
                {copy('If you are still having issues, please read our')}{' '}
                <InlineLink
                  href={DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_SETUP}
                  target='_blank'
                  rel='noopener noreferrer'
                >
                  {copy('article')}
                </InlineLink>{' '}
                {copy('on importing a seed phrase to a YubiKey or')}{' '}
                <InlineLink href={LINK.YUBIKEY_IMPORT_SUPPORT}>
                  {copy('contact support')}
                </InlineLink>
                {copy('.')}
              </>
            ),
          },
        ]}
      />
    </div>
  )
}

function ImportHealth({
  jwt,
  sessionId,
  getExportData,
}: {
  jwt: string
  sessionId: string | null
  getExportData: () => YubiKeyExportData | null
}) {
  const { onForward } = useDeviceNavigation()
  const [status, setStatus] = useState<'idle' | 'loading' | 'done' | 'error'>(
    'idle',
  )
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  // `recoverable` errors can be retried in place (Try Again re-runs the
  // ceremony). `session-lost` means the import session/link is gone, so
  // retrying from this tab can't succeed — the user must restart from
  // their mobile app to generate a new challenge.
  const [errorVariant, setErrorVariant] = useState<
    'recoverable' | 'session-lost'
  >('recoverable')

  const failSessionLost = useCallback((message: string) => {
    setErrorVariant('session-lost')
    setErrorMessage(message)
    setStatus('error')
  }, [])

  const failRecoverable = useCallback((message: string) => {
    setErrorVariant('recoverable')
    setErrorMessage(message)
    setStatus('error')
  }, [])

  // Guard the user's reload edge case: if the parent navigated us to
  // IMPORT_HEALTH but sessionId is missing (e.g. page reloaded with a
  // stale challenge link that 403s on poll), surface the session-lost
  // screen immediately instead of stranding them on the idle "Finish
  // Setup" CTA, which would just round-trip the same error on click.
  useEffect(() => {
    if (sessionId == null && status === 'idle') {
      failSessionLost('Import session is missing. Please restart the flow.')
    }
  }, [sessionId, status, failSessionLost])

  const { fetch: createPendingSignature } = useApi<PendingSignatureChallenge>({
    serviceName: 'vault',
    method: 'PATCH',
    path: 'seedPhraseImportSessions/{id}',
  })

  const { fetch: submitPendingSignature } = useApi<SeedImportSessionResponse>({
    serviceName: 'vault',
    method: 'PUT',
    path: 'seedPhraseImportSessions/{id}/signature',
  })

  const { fetch: completeSession } = useApi<SeedImportSessionResponse>({
    serviceName: 'vault',
    method: 'POST',
    path: 'seedPhraseImportSessions/{id}/complete',
  })

  const { fetch: getSignOptions } = useApi<{
    token: string
    options: import('@simplewebauthn/types').PublicKeyCredentialRequestOptionsJSON
  }>({
    serviceName: 'vault',
    method: 'POST',
    path: 'passkeys/getSignOptions',
  })

  const runCheck = useCallback(async () => {
    const exportData = getExportData()
    if (exportData == null) {
      // The seed wasn't written this tab — no way to verify it from here.
      failSessionLost('Export data missing. Please restart the import flow.')
      return
    }

    if (sessionId == null) {
      // Can't bind signature, can't complete session. Restart from mobile.
      failSessionLost('Import session is missing. Please restart the flow.')
      return
    }

    setStatus('loading')

    // Step 1: Create a pending challenge on the import session. The response
    // includes the cosigner key/walletAccount metadata needed for signing, but
    // does not create a mobile-visible Signature row yet.
    const pendingResult = await createPendingSignature({
      pathData: { id: sessionId },
      body: { signatureCreated: true },
      token: jwt,
    })

    if (pendingResult.error != null || pendingResult.data == null) {
      failRecoverable('Failed to create health check. Please try again.')
      return
    }

    const pendingSignature = pendingResult.data

    // The cosigner Key's path fields are the source of truth for the signing
    // path — walletAccount describes the wallet type, which can diverge from
    // the cosigner's actual derivation (e.g. hardened BIP-45 cosigner xpub in
    // a BIP-49-typed multisig). Surface a recoverable error if the session
    // challenge is unexpectedly missing key data.
    if (pendingSignature.key == null) {
      failRecoverable('Health check signature is missing key data.')
      return
    }

    // walletAccount is needed only for the coinType (wallet-level concern,
    // drives ETH vs BTC signing). The path-derivation fields read off
    // `pendingSignature.key` above, not from here.
    const embeddedWalletAccount = pendingSignature.key.walletAccount

    if (embeddedWalletAccount == null) {
      failRecoverable('Health check signature is missing wallet account data.')
      return
    }

    // Step 2: Get sign options for reading seed from largeBlob. We pass
    // sessionId (not just signatureId) because the passkey hasn't been bound
    // to the Device yet — that linkage happens in `complete` below. Without
    // sessionId, the server's deviceId-keyed lookup returns no credentials
    // and Chrome falls back to the discoverable-credential picker.
    const signOptsResult = await getSignOptions({
      body: { sessionId },
      token: jwt,
    })

    if (signOptsResult.error != null || signOptsResult.data == null) {
      failRecoverable('Failed to get signing options. Please try again.')
      return
    }

    // Step 3: Sign health check message using seed from largeBlob (tap-PIN-tap)
    const ETH_COIN_TYPES = ['ETH', 'ETH-C', 'TETH', 'TETH-C']
    const isEth = ETH_COIN_TYPES.includes(embeddedWalletAccount.coinType)

    const passkeyDevice = await import('@casa/device-signing/src/passkeyDevice')

    let signedMessage
    try {
      signedMessage = await passkeyDevice.getSignedMessage({
        coin: isEth ? 'ETH' : 'BTC',
        keyPathPurpose: pendingSignature.key.keyPathPurpose,
        keyPathPurposeIsHardened:
          pendingSignature.key.keyPathPurposeIsHardened ?? false,
        keyPathCoinType: pendingSignature.key.keyPathCoinType,
        keyPathAccount: pendingSignature.key.keyPathAccount,
        message: pendingSignature.pendingSignatureId,
        authenticationOptions: signOptsResult.data.options,
      })
    } catch {
      failRecoverable(
        'YubiKey signing failed. Make sure your YubiKey is connected and try again.',
      )
      return
    }

    // Step 5: Submit pending proof to server. Completion will re-verify the
    // same bytes and materialize the final Signature row atomically.
    const submitResult = await submitPendingSignature({
      pathData: { id: sessionId },
      body: {
        externalSignatures: [signedMessage],
        deviceType: DEVICE_TYPE.YUBIKEY,
      },
      token: jwt,
    })

    if (submitResult.error != null) {
      failRecoverable('Health check verification failed. Please try again.')
      return
    }

    // Step 6: Complete the session — server atomically validates the full
    // session-binding checklist and transitions the device record to YubiKey.
    // AuthenticationResponseJSON is JSON-serializable but TypeScript can't
    // statically prove its nested fields satisfy useApi's JsonMap bound, so
    // we construct the body as the strongly-typed CompleteSessionBody first
    // (catches misspelled/missing fields at compile time) and only cast at
    // the useApi boundary. Beats the prior `as AnyObject` (yup) cast that
    // bypassed checking entirely.
    const completeBody: CompleteSessionBody = {
      token: exportData.token,
      authenticationResponse: exportData.authenticationResponse,
      blobVersion: exportData.blobVersion,
    }
    const completeResult = await completeSession({
      pathData: { id: sessionId },
      body: completeBody as unknown as JsonMap,
      token: jwt,
    })

    if (completeResult.error != null) {
      failRecoverable('Failed to complete the seed import. Please try again.')
      return
    }

    setStatus('done')
    void onForward(DEVICE_STEPS.YUBIKEY_IMPORT_SUCCESS)
  }, [
    jwt,
    sessionId,
    getExportData,
    createPendingSignature,
    getSignOptions,
    submitPendingSignature,
    completeSession,
    onForward,
    failRecoverable,
    failSessionLost,
  ])

  // Spec Part 6: show an explicit "Almost done" intro before the WebAuthn
  // ceremony fires. The previous implementation auto-ran runCheck() on mount
  // which surprised users with a tap-PIN-tap prompt before they were ready.
  if (status === 'idle') {
    return <ImportHealthIdle onFinishSetup={() => void runCheck()} />
  }

  if (status === 'error') {
    if (errorMessage != null) {
      console.error('YubiKey import health check failed:', errorMessage)
    }
    if (errorVariant === 'session-lost') {
      return <ImportHealthSessionLost />
    }
    return (
      <ImportHealthError
        onTryAgain={() => void runCheck()}
        onStartOver={() => window.location.reload()}
      />
    )
  }

  return <ImportHealthLoading />
}

/**
 * "Import session ended" non-recoverable error. Shown when the BrowserChallenge
 * link is gone or sessionId is missing. No retry CTA because the consumed
 * challenge cannot be resurrected from this tab; the user must initiate a
 * fresh import from their mobile app.
 */
function ImportHealthSessionLost(): React.ReactElement {
  return (
    <div
      css={css`
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 45px;
        width: 100%;
        max-width: 566px;
        margin: 0 auto;
      `}
    >
      <div
        css={css`
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 16px;
        `}
      >
        <WarningAlertIcon />
        <h1
          css={css`
            font-family: 'Maison Neue', sans-serif;
            font-weight: 700;
            font-size: 36px;
            line-height: 1.25;
            color: ${COLOR.WHITE};
            text-align: center;
            margin: 0;
            max-width: 532px;
            word-break: break-word;
          `}
        >
          {copy('Hmm, that didn’t work.')}
        </h1>
        <p
          css={css`
            font-family: 'Maison Neue', sans-serif;
            font-weight: 400;
            font-size: 24px;
            line-height: 1.5;
            color: ${COLOR.WHITE};
            text-align: center;
            margin: 0;
            max-width: 540px;
            word-break: break-word;
          `}
        >
          {copy(
            'For your security, this import session has ended. Please go back to the Casa mobile app and start a new import.',
          )}
        </p>
      </div>
      <SessionLostTipsCard />
    </div>
  )
}

/**
 * Troubleshooting tips card for the session-ended error. Wider than the
 * recoverable error's card and uses a slightly more opaque background.
 */
function SessionLostTipsCard(): React.ReactElement {
  return (
    <div
      css={css`
        background: ${SEED_IMPORT_COLORS.SURFACE_TRANSLUCENT_8};
        border-radius: 12px;
        padding: 16px;
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
        width: 100%;
      `}
    >
      <p
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-weight: 700;
          font-size: 14px;
          line-height: 1.5;
          color: ${COLOR.WHITE};
          margin: 0;
        `}
      >
        {copy('Troubleshooting Tips')}
      </p>
      <TipRow>
        <span
          css={css`
            font-weight: 500;
          `}
        >
          {copy(
            'Make sure you’re opening the link from the most recent email. Older links may have expired',
          )}
        </span>
      </TipRow>
      <TipRow>
        <span
          css={css`
            font-weight: 500;
          `}
        >
          {copy(
            'If you keep running into this, reach out to your Client Advisor.',
          )}
        </span>
      </TipRow>
      <ContactSupportText />
    </div>
  )
}

/**
 * "If you are still having issues…" paragraph used in both the verification
 * loading state and the session-lost error card. Renders the article link to
 * the migration support page and a mailto for contact support.
 */
function ContactSupportText(): React.ReactElement {
  return (
    <p
      css={css`
        font-family: 'Maison Neue', sans-serif;
        font-weight: 400;
        font-size: 14px;
        line-height: 1.5;
        color: ${COLOR.WHITE};
        margin: 0;
        width: 100%;
      `}
    >
      {copy('If you are still having issues, please read our')}{' '}
      <InlineLink
        href='https://support.casa.io/knowledge/how-to-migrate-a-hardware-key-to-a-yubikey'
        target='_blank'
        rel='noopener noreferrer'
      >
        {copy('article')}
      </InlineLink>
      <span
        css={css`
          color: ${SEED_IMPORT_COLORS.TEXT_TRANSLUCENT_80};
        `}
      >
        {' '}
        {copy('on importing a seed phrase to a YubiKey')}
      </span>{' '}
      {copy('or')}{' '}
      <InlineLink
        href={LINK.YUBIKEY_IMPORT_SUPPORT}
        target='_blank'
        rel='noopener noreferrer'
      >
        {copy('contact support.')}
      </InlineLink>
    </p>
  )
}

/**
 * "Set up failed" error state for the verification step. Warning icon,
 * heading, body, primary "Try again" CTA, and a troubleshooting tips card with
 * a "start over" inline link.
 */
function ImportHealthError({
  onTryAgain,
  onStartOver,
}: {
  onTryAgain: () => void
  onStartOver: () => void
}): React.ReactElement {
  return (
    <div
      css={css`
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 45px;
        width: 100%;
        max-width: 540px;
        margin: 0 auto;
      `}
    >
      <div
        css={css`
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 16px;
        `}
      >
        <WarningAlertIcon />
        <h1
          css={css`
            font-family: 'Maison Neue', sans-serif;
            font-weight: 700;
            font-size: 36px;
            line-height: 1.25;
            color: ${COLOR.WHITE};
            text-align: center;
            margin: 0;
            max-width: 532px;
            word-break: break-word;
          `}
        >
          {copy('Hmm, that didn’t work.')}
        </h1>
        <p
          css={css`
            font-family: 'Maison Neue', sans-serif;
            font-weight: 400;
            font-size: 24px;
            line-height: 1.5;
            color: ${COLOR.WHITE};
            text-align: center;
            margin: 0;
            max-width: 540px;
            word-break: break-word;
          `}
        >
          {copy(
            'Please make sure your YubiKey is plugged into your computer and try again.',
          )}
        </p>
      </div>
      <div
        css={css`
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 44px;
          width: 100%;
        `}
      >
        <ContinueButton
          onClick={onTryAgain}
          disabled={false}
          loading={false}
          label='Try Again'
          testId='yubikey-import-try-again'
        />
        <TroubleshootingTipsCard onStartOver={onStartOver} />
      </div>
    </div>
  )
}

/**
 * Translucent troubleshooting tips card shown beneath the Try Again CTA on the
 * verification error screen.
 */
function TroubleshootingTipsCard({
  onStartOver,
}: {
  onStartOver: () => void
}): React.ReactElement {
  return (
    <div
      css={css`
        background: ${SEED_IMPORT_COLORS.SURFACE_TRANSLUCENT_6};
        border-radius: 12px;
        padding: 16px;
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
        width: 100%;
      `}
    >
      <p
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-weight: 700;
          font-size: 14px;
          line-height: 1.5;
          color: ${COLOR.WHITE};
          margin: 0;
        `}
      >
        {copy('Troubleshooting Tips')}
      </p>
      <TipRow>
        <span
          css={css`
            font-weight: 500;
          `}
        >
          {copy('Please make sure you’re tapping the YubiKey when prompted')}
        </span>
      </TipRow>
      <TipRow>
        <span
          css={css`
            font-weight: 400;
          `}
        >
          {copy('The private key may not have been imported correctly. Press')}{' '}
        </span>
        <span
          css={css`
            font-weight: 600;
          `}
        >
          {copy('“Try again”')}
        </span>
        <span
          css={css`
            font-weight: 400;
          `}
        >
          {' '}
          {copy('to re-import it to your YubiKey.')}
        </span>
      </TipRow>
      <p
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-weight: 500;
          font-size: 14px;
          line-height: 1.5;
          color: ${COLOR.WHITE};
          margin: 0;
          width: 100%;
        `}
      >
        {copy('If the issue continues,')}{' '}
        <InlineLink as='button' type='button' onClick={onStartOver}>
          {copy('start over')}
        </InlineLink>{' '}
        {copy('to restart the entire process from the beginning.')}
      </p>
    </div>
  )
}

function TipRow({
  children,
}: {
  children: React.ReactNode
}): React.ReactElement {
  return (
    <div
      css={css`
        display: flex;
        gap: 8px;
        align-items: flex-start;
        width: 100%;
      `}
    >
      <div
        css={css`
          display: flex;
          align-items: flex-start;
          padding-top: 2px;
          flex-shrink: 0;
        `}
      >
        <InfoCircleIcon />
      </div>
      <p
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-size: 14px;
          line-height: 1.5;
          color: ${COLOR.WHITE};
          margin: 0;
          flex: 1 0 0;
          min-width: 0;
        `}
      >
        {children}
      </p>
    </div>
  )
}

/**
 * "Setting up Key" loading state shown during the verification WebAuthn
 * ceremony. 45px light-purple spinner, body copy pointing the user at the
 * passkey popup, and an "Important:" note card with yellow-info-icon callouts.
 */
function ImportHealthLoading(): React.ReactElement {
  return (
    <div
      css={css`
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 45px;
        width: 100%;
        max-width: 540px;
        margin: 0 auto;
      `}
    >
      <div
        css={css`
          /* Use the seed-import light purple spinner color. Override the SVG
             fill rather than fork the loader. */
          svg path {
            fill: ${SEED_IMPORT_COLORS.SPINNER_LIGHT_PURPLE};
          }
        `}
      >
        <SpinningLoader onDark={true} size={45} />
      </div>
      <p
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-weight: 400;
          font-size: 24px;
          line-height: 1.5;
          color: ${COLOR.WHITE};
          text-align: center;
          margin: 0;
          width: 100%;
          word-break: break-word;
        `}
      >
        {copy(
          'Please follow the steps in the passkey popup to finalize your Yubikey setup.',
        )}
      </p>
      <ImportantNoteCard
        rows={[
          {
            text: (
              <>
                {copy(
                  'If you’re using a password manager, it might pop open first. Please close it.',
                )}
              </>
            ),
          },
          {
            text: (
              <>
                {copy(
                  'If you haven’t set up a PIN on your YubiKey, you’ll be prompted to create one. This is required for setup.',
                )}
              </>
            ),
          },
          {
            hideIcon: true,
            text: (
              <>
                {copy('If you are still having issues, please read our')}{' '}
                <InlineLink
                  href={DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_SETUP}
                  target='_blank'
                  rel='noopener noreferrer'
                >
                  {copy('article')}
                </InlineLink>{' '}
                {copy('on importing a seed phrase to a YubiKey or')}{' '}
                <InlineLink href={LINK.YUBIKEY_IMPORT_SUPPORT}>
                  {copy('contact support')}
                </InlineLink>
                {copy('.')}
              </>
            ),
          },
        ]}
      />
    </div>
  )
}

/**
 * Translucent "Important:" card with bulleted info rows. Each row pairs a
 * yellow info icon with body-sm copy. Rows may opt out of the icon.
 */
function ImportantNoteCard({
  rows,
}: {
  rows: { text: React.ReactNode; hideIcon?: boolean }[]
}): React.ReactElement {
  return (
    <div
      css={css`
        background: ${SEED_IMPORT_COLORS.SURFACE_TRANSLUCENT_8};
        border-radius: 12px;
        padding: 16px;
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
        width: 100%;
      `}
    >
      <p
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-weight: 600;
          font-size: 16px;
          line-height: 20px;
          color: ${COLOR.WHITE};
          margin: 0;
          white-space: nowrap;
        `}
      >
        {copy('Important:')}
      </p>
      {rows.map((row, i) => (
        <div
          key={i}
          css={css`
            display: flex;
            gap: 8px;
            align-items: flex-start;
            width: 100%;
          `}
        >
          {row.hideIcon === true ? null : (
            <div
              css={css`
                display: flex;
                align-items: flex-start;
                padding-top: 2px;
                flex-shrink: 0;
              `}
            >
              <InfoCircleIcon />
            </div>
          )}
          <p
            css={css`
              font-family: 'Maison Neue', sans-serif;
              font-weight: 400;
              font-size: 14px;
              line-height: 20px;
              color: ${COLOR.WHITE};
              margin: 0;
              flex: 1 0 0;
              min-width: 0;
            `}
          >
            {row.text}
          </p>
        </div>
      ))}
    </div>
  )
}

/**
 * "Almost done" intro shown after writing the seed to the YubiKey, before the
 * verification tap-PIN-tap ceremony.
 */
function ImportHealthIdle({
  onFinishSetup,
}: {
  onFinishSetup: () => void
}): React.ReactElement {
  return (
    <div
      css={css`
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 45px;
        width: 100%;
        max-width: 540px;
        margin: 0 auto;
      `}
    >
      <div
        css={css`
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 16px;
          width: 100%;
        `}
      >
        <h1
          css={css`
            font-family: 'Maison Neue', sans-serif;
            font-weight: 700;
            font-size: 36px;
            line-height: 1.25;
            letter-spacing: 0;
            color: ${COLOR.WHITE};
            text-align: center;
            margin: 0;
            max-width: 532px;
            word-break: break-word;
          `}
        >
          {copy('Almost done.')}
        </h1>
        <p
          css={css`
            font-family: 'Maison Neue', sans-serif;
            font-weight: 400;
            font-size: 24px;
            line-height: 1.5;
            letter-spacing: 0;
            color: ${COLOR.WHITE};
            text-align: center;
            margin: 0;
            max-width: 540px;
            word-break: break-word;
          `}
        >
          {copy(
            'Now you’ll re-authenticate with your YubiKey to verify that the private key was imported successfully.',
          )}
        </p>
        <ImportHealthStepsCard />
      </div>
      <ContinueButton
        onClick={onFinishSetup}
        disabled={false}
        loading={false}
        label='Finish Setup'
        testId='yubikey-import-finish-setup'
      />
    </div>
  )
}

/**
 * Translucent rounded card listing the three actions the user is about to
 * perform on their YubiKey.
 */
function ImportHealthStepsCard(): React.ReactElement {
  return (
    <div
      css={css`
        background: ${SEED_IMPORT_COLORS.SURFACE_TRANSLUCENT_8};
        border-radius: 12px;
        padding: 16px 25px;
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: 7px;
        width: 368px;
        max-width: 100%;
      `}
    >
      <p
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-weight: 600;
          font-size: 18px;
          line-height: 1.5;
          color: ${COLOR.WHITE};
          margin: 0;
          white-space: nowrap;
        `}
      >
        {copy('After you click “Finish Set up”:')}
      </p>
      <ImportHealthStep number={1} label='Tap your YubiKey' />
      <ImportHealthStep number={2} label='Enter your PIN' />
      <ImportHealthStep number={3} label='Tap your YubiKey again' />
    </div>
  )
}

function ImportHealthStep({
  number,
  label,
}: {
  number: number
  label: string
}): React.ReactElement {
  return (
    <div
      css={css`
        display: flex;
        align-items: center;
        gap: 10px;
        width: 100%;
      `}
    >
      <div
        css={css`
          width: 18px;
          height: 18px;
          border-radius: 999px;
          background: ${SEED_IMPORT_COLORS.CYAN_STEP_PILL};
          display: flex;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;
        `}
      >
        <span
          css={css`
            font-family: 'Maison Neue', sans-serif;
            font-weight: 700;
            font-size: 12px;
            line-height: 1.5;
            color: ${SEED_IMPORT_COLORS.BLACK_ON_LIGHT};
          `}
        >
          {number}
        </span>
      </div>
      <p
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-weight: 500;
          font-size: 18px;
          line-height: 1.5;
          color: ${COLOR.WHITE};
          margin: 0;
          flex: 1 0 0;
          min-width: 0;
        `}
      >
        {label}
      </p>
    </div>
  )
}

/**
 * "Confirmation / Success" screen with a cyan checkmark, bold heading, and
 * body copy.
 */
function ImportSuccess(): React.ReactElement {
  return (
    <div
      css={css`
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 16px;
        width: 100%;
        max-width: 540px;
        margin: 0 auto;
      `}
    >
      <SuccessCheckIcon />
      <h1
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-weight: 700;
          font-size: 36px;
          line-height: 1.25;
          color: ${COLOR.WHITE};
          text-align: center;
          margin: 0;
          word-break: break-word;
        `}
      >
        {copy('Success')}
      </h1>
      <p
        css={css`
          font-family: 'Maison Neue', sans-serif;
          font-weight: 400;
          font-size: 24px;
          line-height: 1.5;
          color: ${COLOR.WHITE};
          text-align: center;
          margin: 0;
          width: 100%;
          word-break: break-word;
        `}
      >
        {copy('Your key has been set up.')}
        <br />
        {copy('You can close this tab.')}
      </p>
    </div>
  )
}
