import { PasskeyErrorCodes } from '@casa/device-signing/src/utils/passkeyUtils'
import { css } from '@emotion/react'
import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import CopyToClipboard from 'react-copy-to-clipboard'
import toast from 'react-hot-toast'

import ButtonAsLink from 'src/components/ButtonAsLink'
import SeedPhraseVerifyWord from 'src/components/SeedPhraseVerifyWord'
import SeedPhraseWords from 'src/components/SeedPhraseWords'
import Spacer from 'src/components/Spacer'
import COLOR from 'src/constants/color'
import LINK from 'src/constants/link'
import { MIN_MEDIA } from 'src/constants/media-query'
import {
  DefaultButton,
  SecondaryButton,
} from 'src/features/device-signing/components/Buttons'
import DeviceConfirmation from 'src/features/device-signing/components/DeviceConfirmation'
import {
  TroubleshootingFooter,
  WarningBanner,
} from 'src/features/device-signing/components/HelpBanners'
import PasskeyLoading from 'src/features/device-signing/components/PasskeyLoading'
import ScamWarningBanner from 'src/features/device-signing/components/ScamWarningBanner'
import * as DEVICE_LINKS from 'src/features/device-signing/constants/link'
import { DEVICE_STEPS } from 'src/features/device-signing/constants/steps'
import useDeviceNavigation from 'src/features/device-signing/hooks/useDeviceNavigation'
import useSeedMemoryHygiene from 'src/features/device-signing/hooks/useSeedMemoryHygiene'
import { useWebWallet } from 'src/features/device-signing/hooks/useWebWallet'
import { supportReferenceFor } from 'src/features/device-signing/utils/parseError'
import useTranslate from 'src/hooks/useTranslate'
import { ReactComponent as AlertCircleThin } from 'src/images/alert-circle-thin-icon.svg'
import { ReactComponent as CheckmarkCircleThin } from 'src/images/checkmark-circle-thin-icon.svg'
import { ReactComponent as YubikeyIcon } from 'src/images/yubikey-icon.svg'
import { SeedPhrase } from 'src/types/Wallet'

/**
 * Controls display for a seed phrase display and test process using a passkey device. This must
 * be kept distinct from the Ledger and Trezor (and other hardware wallet) setup processes
 * because of server option calls, and error handling about passkey-specific interactions
 * issues.
 */
export default function YubikeyExport() {
  const { step, onForward } = useDeviceNavigation()
  const { resetPhrase, phrase } = useWebWallet()
  const [expired, setExpired] = useState(false)

  /**
   * Whether a mnemonic actually reached the screen during this attempt. The
   * timer is armed on LOAD too (see below), so without this an expiry while the
   * read is still pending would tell the user we hid a seed phrase they were
   * never shown. Read through a ref because `onExpire` is held by the hook and
   * must not be re-created on every phrase change.
   */
  const phraseWasShownRef = useRef(false)
  useEffect(() => {
    if (phrase != null) {
      phraseWasShownRef.current = true
    }
  }, [phrase])

  /**
   * The mnemonic read off the YubiKey's largeBlob lands in WebWallet context
   * state (`phrase`). Nothing in this flow cleared it, so it stayed reachable
   * in a live React tree until the whole provider unmounted — long after the
   * user finished reading it. Bound that window: drop it on unmount, on page
   * navigation, and after an inactivity timeout.
   *
   * VIEW and TEST are the steps that hold the mnemonic. LOAD is included
   * because `getSeedPhrase` resolves into context state while that step is
   * mounted. START, SUCCESS and ERROR are excluded — the phrase is either not
   * read yet or already cleared.
   */
  const seedOnScreen =
    step === DEVICE_STEPS.YUBIKEY_EXPORT_LOAD ||
    step === DEVICE_STEPS.YUBIKEY_EXPORT_VIEW ||
    step === DEVICE_STEPS.YUBIKEY_EXPORT_TEST

  const onExpire = useCallback(() => {
    // Only claim we hid the seed phrase if one was actually displayed.
    setExpired(phraseWasShownRef.current)
    void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_ERROR)
  }, [onForward])

  useSeedMemoryHygiene({
    active: seedOnScreen,
    clearSecrets: resetPhrase,
    onExpire,
  })

  /**
   * Starting a fresh attempt clears the expiry state. Without this, TRY AGAIN
   * after one expiry left `expired` true, so a genuine device error on the next
   * read (unplugged YubiKey, dismissed prompt) still rendered the "we hid your
   * seed phrase" subtitle instead of the applicable error.
   *
   * Keyed on LOAD, not on `seedOnScreen`: every new read begins at LOAD (TRY
   * AGAIN forwards there), whereas resetting for the whole seed-bearing range
   * would also fire when the flow is entered directly at VIEW and would clobber
   * `phraseWasShownRef` for a phrase that is already on screen.
   */
  useEffect(() => {
    if (step === DEVICE_STEPS.YUBIKEY_EXPORT_LOAD) {
      setExpired(false)
      phraseWasShownRef.current = false
    }
  }, [step])

  /**
   * A seed step with no phrase — the window between clearing and the step
   * moving, or a page restored from the back-forward cache with its phrase
   * dropped by pagehide. Render the error screen directly instead of asking the
   * views to navigate their way out.
   *
   * This MUST be a render decision, not a navigation. `onForwardReady` is only
   * ever called from DeviceConfirmation's exit animation, so a screen that
   * renders nothing can never complete a pending navigation: the step would
   * stay put, the view would render again with the phrase still missing, and
   * navigating from the render body appends to Recoil's stepsPath every pass —
   * new state, another notification, and React eventually throws "Maximum
   * update depth exceeded". Rendering ExportError mounts a DeviceConfirmation,
   * so any navigation already in flight can finish.
   */
  const seedMissing =
    phrase == null &&
    (step === DEVICE_STEPS.YUBIKEY_EXPORT_VIEW ||
      step === DEVICE_STEPS.YUBIKEY_EXPORT_TEST)

  if (seedMissing) {
    return <ExportError expired={expired} />
  }

  switch (step) {
    case DEVICE_STEPS.YUBIKEY_EXPORT_START:
      return <ExportStart />
    case DEVICE_STEPS.YUBIKEY_EXPORT_LOAD:
      return <ExportLoading />
    case DEVICE_STEPS.YUBIKEY_EXPORT_VIEW:
      return <ExportView />
    case DEVICE_STEPS.YUBIKEY_EXPORT_TEST:
      return <ExportTest />
    case DEVICE_STEPS.YUBIKEY_EXPORT_SUCCESS:
      return <ExportSuccess />
    case DEVICE_STEPS.YUBIKEY_EXPORT_ERROR:
    default:
      return <ExportError expired={expired} />
  }
}

// Shows the initial screen for setting up a YubiKey device
export function ExportStart() {
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()

  /**
   * The presence of an in-memory credentialId indicates that the user has completed a setup flow,
   * without this, a user may have entered the page directly via a backup flow
   */
  const { credentialId } = useWebWallet()

  const onContinue = () => {
    void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_LOAD)
  }

  const onSkip = () => {
    void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_SUCCESS)
  }

  return (
    <DeviceConfirmation
      titleIcon={<YubikeyIcon />}
      key={DEVICE_STEPS.YUBIKEY_START}
      title={translate('yubikey_export_start_title')}
      subTitle={translate('yubikey_export_start_subtitle')}
      primaryButton={
        <DefaultButton onClick={onContinue} data-testid='continue-button'>
          {translate('continue')}
        </DefaultButton>
      }
      secondaryButton={
        <SecondaryButton
          onClick={onSkip}
          css={css`
            width: fit-content;
          `}
          data-testid='yubikey-export-later-button'
        >
          {translate('yubikey_export_cta_later')}
        </SecondaryButton>
      }
    >
      <Fragment>
        <Spacer unit={12} />
        <ScamWarningBanner />
        {credentialId == null ? (
          <>
            <Spacer unit={12} />
            <WarningBanner
              warningLabel={translate('important')}
              warnings={[<CopyLocation />]}
            />
          </>
        ) : (
          <Fragment />
        )}
      </Fragment>
    </DeviceConfirmation>
  )
}

export function ExportLoading() {
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()
  const { getSeedPhrase, phraseError, phrase } = useWebWallet()

  const [passkeyPrompted, setPasskeyPrompted] = useState(false)

  useEffect(() => {
    if (passkeyPrompted === true) {
      return
    }

    setPasskeyPrompted(true)
    void getSeedPhrase()
  }, [passkeyPrompted, getSeedPhrase])

  useEffect(() => {
    const isSuccessful = phrase !== null && phraseError == null

    if (isSuccessful === true) {
      void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_VIEW)
      return
    }

    if (phraseError != null) {
      void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_ERROR)
      return
    }
  }, [phraseError, phrase, onForward])

  return (
    <PasskeyLoading
      key={DEVICE_STEPS.YUBIKEY_EXPORT_LOAD}
      subTitle={translate('yubikey_setup_loading_body')}
      warnings={[
        translate('yubikey_warning_password_manager'),
        translate('yubikey_warning_prompt_selection'),
      ]}
    />
  )
}

// Toggle a seed phrase view after setup
function ExportView() {
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()
  const { phrase } = useWebWallet()

  const onContinue = () => {
    void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_TEST)
  }

  const onSkip = () => {
    void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_SUCCESS)
  }

  // Defense in depth only: the parent already routes a missing phrase to the
  // error screen before this renders. Never navigate from here — see the
  // seedMissing comment in YubikeyExport for why that loops.
  if (phrase == null) {
    return <Fragment />
  }

  return (
    <DeviceConfirmation
      elementCss={extendedContainerStyles}
      key={DEVICE_STEPS.YUBIKEY_EXPORT_VIEW}
      title={translate('yubikey_export_view_title')}
      subTitle={translate('yubikey_export_view_subtitle')}
      interaction={<SeedPhraseWords seedPhrase={phrase as SeedPhrase} />}
      primaryButton={
        <DefaultButton
          onClick={onContinue}
          data-testid='yubikey-export-view-cta-button'
        >
          {translate('yubikey_export_view_cta')}
        </DefaultButton>
      }
      secondaryButton={
        <SecondaryButton onClick={onSkip} data-testid='skip-button'>
          {translate('skip')}
        </SecondaryButton>
      }
    />
  )
}

// Controls minimum toast frequency for consecutive incorrect seed phrase words selections
const VERIFY_ERROR_RATE_LIMIT_MS = 5000

/**
 * Success state for the Yubikey setup process with the
 * option to continue to a seedPhrase recovery process
 * depending on a feature flag
 */
function ExportTest() {
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()
  const { phrase, phraseConfirmed, onConfirmPhrase } = useWebWallet()
  const [selected, setSelected] = useState<number | null>(null)
  const [isIncorrect, setIsIncorrect] = useState<boolean>(false)

  const onGoBack = () => {
    void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_VIEW)
  }

  const onSkip = () => {
    void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_SUCCESS)
  }

  const targetIndex = useMemo(() => {
    return phrase != null ? Math.floor(Math.random() * phrase.length) : 0
  }, [phrase])

  useEffect(() => {
    if (selected === targetIndex) {
      onConfirmPhrase()
    }

    if (selected != null && selected !== targetIndex) {
      setIsIncorrect(true)
    }
  }, [selected, targetIndex, onConfirmPhrase])

  /**
   * Rate-limited toast display on incorrect seed phrase selections. Multiple
   * consecutive incorrect selections will not trigger multiple toasts if one
   * is already displayed.
   */
  useEffect(() => {
    if (isIncorrect) {
      toast.error(translate('yubikey_export_test_error'))
      setTimeout(() => setIsIncorrect(false), VERIFY_ERROR_RATE_LIMIT_MS)
    }
  }, [isIncorrect, translate])

  useEffect(() => {
    if (phraseConfirmed === true) {
      toast.dismiss()
      void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_SUCCESS)
    }
  }, [phraseConfirmed, onForward])

  // As in ExportView: the parent handles this, and navigating from a render
  // body that returns no DeviceConfirmation cannot complete.
  if (phrase == null) {
    return <Fragment />
  }

  return (
    <DeviceConfirmation
      key={DEVICE_STEPS.YUBIKEY_EXPORT_TEST}
      title={translate('yubikey_export_test_title')}
      elementCss={[
        extendedContainerStyles,
        css`
          width: auto;
        `,
      ]}
      subTitle={translate('yubikey_export_test_subtitle')}
      interaction={
        <SeedPhraseVerifyWord
          seedPhrase={phrase as SeedPhrase}
          verify={targetIndex}
          selected={selected}
          setSelected={setSelected}
        />
      }
      primaryButton={
        <DefaultButton onClick={onGoBack} data-testid='go-back-button'>
          {translate('go_back')}
        </DefaultButton>
      }
      secondaryButton={
        <SecondaryButton
          onClick={onSkip}
          data-testid='yubikey-export-test-skip-button'
        >
          {translate('yubikey_export_test_cta_skip')}
        </SecondaryButton>
      }
    ></DeviceConfirmation>
  )
}

/**
 * Success state for the Yubikey setup process with the
 * option to continue to a seedPhrase recovery process
 * depending on a feature flag
 */
function ExportSuccess() {
  const { translate } = useTranslate()
  const { phraseConfirmed } = useWebWallet()
  const { subtitle, additionalInstructions } = phraseConfirmed
    ? {
        subtitle: translate('yubikey_export_success_subtitle_verified'),
        additionalInstructions: translate('yubikey_export_success_subtitle'),
      }
    : {
        subtitle: translate('yubikey_export_success_subtitle'),
        additionalInstructions: undefined,
      }

  return (
    <DeviceConfirmation
      titleIcon={
        <CheckmarkCircleThin
          width='54px'
          height='54px'
          css={css`
            path {
              fill: ${COLOR.TEAL_500};
            }
          `}
        />
      }
      key={DEVICE_STEPS.YUBIKEY_SUCCESS}
      title={translate('yubikey_setup_success_title')}
      subTitle={subtitle}
      additionalInstructions={additionalInstructions}
    />
  )
}

// Error handling for the Yubikey signing process
function ExportError({ expired = false }: { expired?: boolean }) {
  const { phraseError, resetErrors } = useWebWallet()
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()

  const onTryAgain = useCallback(async () => {
    resetErrors()
    await onForward(DEVICE_STEPS.YUBIKEY_EXPORT_LOAD)
  }, [onForward, resetErrors])

  // An inactivity expiry is not a device failure, so it must not tell the user
  // to check that their YubiKey is plugged in. Say what actually happened.
  const isWrongYubikey = phraseError?.code === PasskeyErrorCodes.FAILED_READ
  const subtitle = expired
    ? translate('yubikey_export_expired')
    : isWrongYubikey
      ? translate('yubikey_error_wrong_yubikey')
      : translate('yubikey_error_dismissed')
  const errorReference =
    expired || isWrongYubikey ? undefined : supportReferenceFor(phraseError)

  const supportInfo = translate('yubikey_error_footer_seed', {
    troubleshootingLink: DEVICE_LINKS.SEED_PHRASE_EXPOSURE,
    supportLink: LINK.YUBIKEY_EXPORT_SUPPORT,
  })

  return (
    <DeviceConfirmation
      errorReference={errorReference}
      key={DEVICE_STEPS.YUBIKEY_EXPORT_ERROR}
      titleIcon={
        <AlertCircleThin
          width='54px'
          height='54px'
          css={css`
            path {
              fill: ${COLOR.YELLOW_500};
            }
          `}
        />
      }
      title={translate('yubikey_error_title')}
      subTitle={subtitle}
      primaryButton={
        <DefaultButton onClick={onTryAgain} data-testid='try-again-button'>
          {translate('try_again')}
        </DefaultButton>
      }
    >
      <Fragment>
        <Spacer unit={8} />
        <TroubleshootingFooter supportInfo={supportInfo} />
      </Fragment>
    </DeviceConfirmation>
  )
}

const COPY_BUTTON_RATE_LIMIT_MS = 5000

export function CopyLocation() {
  const { translate } = useTranslate()
  const [copied, setCopied] = useState(false)

  // Rate limit to prevent spamming the user with toasts on multiple clicks
  useEffect(() => {
    if (copied) {
      toast.success(translate('copied'))
      setTimeout(() => setCopied(false), COPY_BUTTON_RATE_LIMIT_MS)
    }
  }, [copied, translate])

  const onCopy = useCallback(() => {
    if (!copied) {
      setCopied(true)
    }
  }, [copied])

  /**
   * onClick handler is okay to be undefined since the CopyToClipboard component handles children
   * behavior. It must be kept as a button for accessibility.
   */
  return (
    <span css={paragraphStyle}>
      {translate('yubikey_incognito_tip')}
      <CopyToClipboard text={window.location.toString()} onCopy={onCopy}>
        <ButtonAsLink
          data-testid='login-button-passkey-help-close'
          onClick={() => undefined}
        >
          {translate('yubikey_copy_link')}
        </ButtonAsLink>
      </CopyToClipboard>
    </span>
  )
}

const paragraphStyle = css`
  font-size: 16px;
  font-weight: 500;
  color: ${COLOR.WHITE};

  button {
    text-decoration-color: ${COLOR.PURPLE_300};
    color: ${COLOR.PURPLE_300};
    font-weight: 700;
    font-size: 16px;
    padding: 0 4px;
  }
`

/**
 *  The longer headline and seed phrase view requires a wider container
 *  and distinct button layout. These files must override the default parent
 *  that holds a fixed, narrow width.
 *
 * The #animated-cta-content resets the flex direction for the nested button
 * wrapper, which is needed where seed phrase display components are used.
 */
const extendedContainerStyles = css`
  ${MIN_MEDIA.$800} {
    width: 675px;
    left: -40px;
    position: relative;
  }

  & #animated-cta-content {
    display: flex;
    flex-direction: column;
    align-items: center;
  }
`
