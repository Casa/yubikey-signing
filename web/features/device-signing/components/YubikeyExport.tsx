import { PasskeyErrorCodes } from '@casa/device-signing/src/utils/passkeyUtils'
import { css } from '@emotion/react'
import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
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
import * as DEVICE_LINKS from 'src/features/device-signing/constants/link'
import { DEVICE_STEPS } from 'src/features/device-signing/constants/steps'
import useDeviceNavigation from 'src/features/device-signing/hooks/useDeviceNavigation'
import { useWebWallet } from 'src/features/device-signing/hooks/useWebWallet'
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
  const { step } = useDeviceNavigation()

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
      return <ExportError />
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
        <DefaultButton onClick={onContinue}>
          {translate('continue')}
        </DefaultButton>
      }
      secondaryButton={
        <SecondaryButton
          onClick={onSkip}
          css={css`
            width: fit-content;
          `}
        >
          {translate('yubikey_export_cta_later')}
        </SecondaryButton>
      }
    >
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

  return (
    <DeviceConfirmation
      elementCss={extendedContainerStyles}
      key={DEVICE_STEPS.YUBIKEY_EXPORT_VIEW}
      title={translate('yubikey_export_view_title')}
      subTitle={translate('yubikey_export_view_subtitle')}
      interaction={<SeedPhraseWords seedPhrase={phrase as SeedPhrase} />}
      primaryButton={
        <DefaultButton onClick={onContinue}>
          {translate('yubikey_export_view_cta')}
        </DefaultButton>
      }
      secondaryButton={
        <SecondaryButton onClick={onSkip}>{translate('skip')}</SecondaryButton>
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

  if (phrase == null) {
    void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_ERROR)
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
        <DefaultButton onClick={onGoBack}>{translate('go_back')}</DefaultButton>
      }
      secondaryButton={
        <SecondaryButton onClick={onSkip}>
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
function ExportError() {
  const { phraseError, resetErrors } = useWebWallet()
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()

  const onTryAgain = useCallback(async () => {
    resetErrors()
    await onForward(DEVICE_STEPS.YUBIKEY_EXPORT_LOAD)
  }, [onForward, resetErrors])

  const subtitle =
    phraseError?.code === PasskeyErrorCodes.FAILED_READ
      ? translate('yubikey_error_wrong_yubikey')
      : translate('yubikey_error_dismissed')

  const supportInfo = translate('yubikey_error_footer_seed', {
    troubleshootingLink: DEVICE_LINKS.SEED_PHRASE_EXPOSURE,
    supportLink: LINK.YUBIKEY_EXPORT_SUPPORT,
  })

  return (
    <DeviceConfirmation
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
        <DefaultButton onClick={onTryAgain}>
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
