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

import { SpinningLoader } from 'src/components/Loaders'
import Spacer from 'src/components/Spacer'
import COLOR from 'src/constants/color'
import { DEVICE_TYPE, Device } from 'src/constants/device'
import LINK from 'src/constants/link'
import {
  DefaultButton,
  SecondaryButton,
} from 'src/features/device-signing/components/Buttons'
import DeviceConfirmation from 'src/features/device-signing/components/DeviceConfirmation'
import {
  InstructionsBanner,
  WarningBanner,
} from 'src/features/device-signing/components/HelpBanners'
import { TroubleshootingFooter } from 'src/features/device-signing/components/HelpBanners'
import PasskeyLoading from 'src/features/device-signing/components/PasskeyLoading'
import RequireChrome from 'src/features/device-signing/components/RequireChrome'
import YubikeyExport, {
  CopyLocation,
} from 'src/features/device-signing/components/YubikeyExport'
import * as DEVICE_LINKS from 'src/features/device-signing/constants/link'
import { DEVICE_STEPS } from 'src/features/device-signing/constants/steps'
import useDeviceNavigation from 'src/features/device-signing/hooks/useDeviceNavigation'
import {
  useWebWallet,
  WebWalletProvider,
} from 'src/features/device-signing/hooks/useWebWallet'
import { supportReferenceFor } from 'src/features/device-signing/utils/parseError'
import useTranslate from 'src/hooks/useTranslate'
import { ReactComponent as AlertCircleThin } from 'src/images/alert-circle-thin-icon.svg'
import { ReactComponent as CheckmarkCircleThin } from 'src/images/checkmark-circle-thin-icon.svg'
import { ReactComponent as YubikeyIcon } from 'src/images/yubikey-icon.svg'

// The provider-wrapped controller of all Yubikey register steps
export default function YubikeyCopy({
  device,
  jwt,
}: {
  device: Device
  jwt: string
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
          <YubikeyCopyFlow />
        </RequireChrome>
      </section>
    </WebWalletProvider>
  )
}

function YubikeyCopyFlow() {
  const { step }: { step: DEVICE_STEPS } = useDeviceNavigation()

  switch (step) {
    case DEVICE_STEPS.DEVICE_SELECTION:
    case DEVICE_STEPS.YUBIKEY_COPY_EXPORT_START:
      return <YubikeyExportStart />
    case DEVICE_STEPS.YUBIKEY_COPY_EXPORT_LOAD:
      return <YubikeyExportLoading />
    case DEVICE_STEPS.YUBIKEY_START:
      return <YubikeyCopyStart />
    case DEVICE_STEPS.YUBIKEY_INTERACT_PASSKEY:
      return <YubikeyPasskeyLoading />
    case DEVICE_STEPS.YUBIKEY_SETUP_CONFIRM:
      return <YubikeySetupConfirm />
    case DEVICE_STEPS.YUBIKEY_INTERACT_WALLET:
      return <YubikeyWalletLoading />
    case DEVICE_STEPS.YUBIKEY_SUCCESS:
      return <YubikeySuccess />
    case DEVICE_STEPS.YUBIKEY_EXPORT_START:
    case DEVICE_STEPS.YUBIKEY_EXPORT_LOAD:
    case DEVICE_STEPS.YUBIKEY_EXPORT_VIEW:
    case DEVICE_STEPS.YUBIKEY_EXPORT_TEST:
    case DEVICE_STEPS.YUBIKEY_EXPORT_SUCCESS:
    case DEVICE_STEPS.YUBIKEY_EXPORT_ERROR:
      return <YubikeyExport />
    default:
      return <YubikeyError />
  }
}

function YubikeyExportStart() {
  const { translate } = useTranslate()

  const { passkeyError, credentialId } = useWebWallet()
  const { onForward } = useDeviceNavigation()

  const onContinue = () => {
    void onForward(DEVICE_STEPS.YUBIKEY_COPY_EXPORT_LOAD)
  }

  useEffect(() => {
    if (passkeyError != null) {
      void onForward(DEVICE_STEPS.YUBIKEY_ERROR)
    }
  }, [passkeyError, onForward])

  return (
    <DeviceConfirmation
      titleIcon={<YubikeyIcon />}
      key={DEVICE_STEPS.YUBIKEY_START}
      title={translate('yubikey_sign_start_title')}
      primaryButton={
        <DefaultButton onClick={onContinue} data-testid='continue-button'>
          {translate('continue')}
        </DefaultButton>
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

function YubikeyExportLoading() {
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
      void onForward(DEVICE_STEPS.YUBIKEY_START)
      return
    }

    if (phraseError != null) {
      void onForward(DEVICE_STEPS.YUBIKEY_ERROR)
      return
    }
  }, [phraseError, phrase, onForward])

  return (
    <PasskeyLoading
      key={DEVICE_STEPS.YUBIKEY_EXPORT_LOAD}
      subTitle={translate('yubikey_setup_loading_body')}
    />
  )
}

function YubikeyCopyStart() {
  const { translate } = useTranslate()

  const { passkeyError, credentialId } = useWebWallet()
  const { onForward } = useDeviceNavigation()

  const onContinue = () => {
    void onForward(DEVICE_STEPS.YUBIKEY_INTERACT_PASSKEY)
  }

  useEffect(() => {
    if (passkeyError != null) {
      void onForward(DEVICE_STEPS.YUBIKEY_ERROR)
    }
  }, [passkeyError, onForward])

  return (
    <DeviceConfirmation
      titleIcon={<YubikeyIcon />}
      key={DEVICE_STEPS.YUBIKEY_START}
      title={translate('yubikey_copy_start_title')}
      primaryButton={
        <DefaultButton onClick={onContinue} data-testid='continue-button'>
          {translate('continue')}
        </DefaultButton>
      }
    >
      {credentialId == null ? (
        <>
          <Spacer unit={12} />
          <WarningBanner
            warningLabel={translate('important')}
            warnings={[
              translate('yubikey_setup_tip', {
                checkFirmwareLink: DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_FIRMWARE,
              }),
            ]}
          />
        </>
      ) : (
        <Fragment />
      )}
    </DeviceConfirmation>
  )
}

// Loading state in charge of showing the browser spinner during the attestation call
export function YubikeyPasskeyLoading() {
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()
  const { createPasskey } = useWebWallet()

  const [passkeyPrompted, setPasskeyPrompted] = useState(false)

  useEffect(() => {
    if (passkeyPrompted === true) {
      return
    }

    setPasskeyPrompted(true)
    void createPasskey()
  }, [passkeyPrompted, createPasskey])

  const { passkeyLoading, passkeyError, credentialId } = useWebWallet()

  useEffect(() => {
    const isSuccessful = credentialId !== null && passkeyError == null

    if (isSuccessful === true) {
      void onForward(DEVICE_STEPS.YUBIKEY_SETUP_CONFIRM)
      return
    }

    if (passkeyError != null) {
      void onForward(DEVICE_STEPS.YUBIKEY_ERROR)
      return
    }
  }, [passkeyLoading, passkeyError, credentialId, onForward])

  return (
    <PasskeyLoading
      key={DEVICE_STEPS.YUBIKEY_INTERACT_PASSKEY}
      subTitle={translate('yubikey_setup_loading_body')}
      warnings={[
        translate('yubikey_warning_password_manager'),
        translate('yubikey_warning_pin'),
      ]}
    />
  )
}

// Success state for the passkey creation process
function YubikeySetupConfirm() {
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()

  const onContinue = () => {
    void onForward(DEVICE_STEPS.YUBIKEY_INTERACT_WALLET)
  }

  return (
    <DeviceConfirmation
      key={DEVICE_STEPS.YUBIKEY_SETUP_CONFIRM}
      title={translate('yubikey_reauth_title')}
      subTitle={translate('yubikey_reauth_body')}
      interaction={
        <InstructionsBanner
          label={translate('yubikey_reauth_instruction_title')}
          instructions={[
            translate('yubikey_reauth_instruction_1'),
            translate('yubikey_reauth_instruction_2'),
            translate('yubikey_reauth_instruction_3'),
          ]}
        />
      }
      primaryButton={
        <DefaultButton onClick={onContinue} data-testid='continue-button'>
          {translate('yubikey_reauth_continue')}
        </DefaultButton>
      }
    />
  )
}

// After the passkey prompt, hold the spinner for at least 3 seconds
const WALLET_LOADING_TIME_MIN_MS = 3000

/**
 * Loading state in charge of showing the browser spinner during the
 * webauthn authentication call to write a seedPhrase to the device
 */
function YubikeyWalletLoading() {
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()
  const {
    xPub,
    createWallet,
    walletError,
    deviceUpdateLoading,
    phrase: seedPhrase,
  } = useWebWallet()

  const [passkeyPrompted, setPasskeyPrompted] = useState(false)
  const [minimumTimePassed, setMinimumTimePassed] = useState<boolean | null>(
    null,
  )
  const timerRef = useRef<number | null>(null)

  useEffect(() => {
    if (passkeyPrompted === true) {
      return
    }

    setPasskeyPrompted(true)
    void createWallet(seedPhrase?.join(' '))
  }, [passkeyPrompted, createWallet, seedPhrase])

  /**
   * Once deviceUpdateLoading is true, start a timer to ensure the spinner hold
   * for at least 3 seconds before moving to the next step
   */
  useEffect(() => {
    // If loading has begun, start the timer
    if (deviceUpdateLoading && timerRef.current === null) {
      setMinimumTimePassed(false)

      timerRef.current = window.setTimeout(() => {
        setMinimumTimePassed(true)
      }, WALLET_LOADING_TIME_MIN_MS)
    }

    return () => {
      if (!deviceUpdateLoading && timerRef.current !== null) {
        window.clearTimeout(timerRef.current)
        timerRef.current = null
      }
    }
  }, [deviceUpdateLoading])

  useEffect(() => {
    const isSuccessful =
      minimumTimePassed === true && xPub != null && walletError == null

    if (isSuccessful) {
      void onForward(DEVICE_STEPS.YUBIKEY_SUCCESS)
      return
    }

    if (walletError != null) {
      void onForward(DEVICE_STEPS.YUBIKEY_ERROR)
      return
    }
  }, [xPub, createWallet, walletError, onForward, minimumTimePassed])

  if (deviceUpdateLoading || timerRef.current !== null) {
    return (
      <DeviceConfirmation
        title={translate('yubikey_reauth_copy_loading_title')}
        interaction={<SpinningLoader size={45} />}
      />
    )
  }

  return (
    <PasskeyLoading
      key={DEVICE_STEPS.YUBIKEY_INTERACT_WALLET}
      subTitle={translate('yubikey_reauth_loading_body')}
      warnings={[
        translate('yubikey_warning_password_manager'),
        translate('yubikey_warning_prompt_selection'),
      ]}
    />
  )
}

/**
 * Success state for the Yubikey setup process with the
 * option to continue to a seedPhrase recovery process
 * depending on a feature flag
 */
function YubikeySuccess() {
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()

  const onExport = () => {
    void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_VIEW)
  }

  const onSkip = () => {
    void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_SUCCESS)
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
      title={translate('yubikey_copy_success_title')}
      subTitle={translate('yubikey_setup_success_subtitle')}
      warnings={[<SeedWarning />]}
      primaryButton={
        <DefaultButton
          onClick={onExport}
          data-testid='yubikey-setup-success-cta-export'
        >
          {translate('yubikey_setup_success_cta_export')}
        </DefaultButton>
      }
      secondaryButton={
        <SecondaryButton
          onClick={onSkip}
          data-testid='yubikey-setup-success-skip-button'
        >
          {translate('yubikey_setup_success_cta_skip')}
        </SecondaryButton>
      }
    />
  )
}

/**
 * Adds translation string with styled formatting. Line break and alignment
 * interpolations are not supported in the translation renderer
 */
function SeedWarning() {
  const { translate } = useTranslate()

  return (
    <>
      <strong>{translate('yubikey_setup_success_instruction')}</strong>
      <br />
      {translate('yubikey_setup_success_info', {
        link: DEVICE_LINKS.SOVEREIGN_RECOVERY,
      })}
    </>
  )
}

/**
 * A general error view to handle a parsed Passkey error to
 * show the user a message and a call to action to try again
 */
function YubikeyError() {
  const { passkeyError, walletError, resetErrors, phraseError } = useWebWallet()
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()

  const { subtitle, tips, errorReference } = useMemo(() => {
    if (walletError?.code != null) {
      switch (walletError.code) {
        case PasskeyErrorCodes.USER_EXITED:
          return { subtitle: translate('yubikey_error_dismissed'), tip: null }
        case PasskeyErrorCodes.FAILED_WRITE:
          return {
            subtitle: translate('yubikey_error_invalid_firmware', {
              checkFirmwareLink: DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_FIRMWARE,
            }),
            tips: [translate('yubikey_error_tip_failed_write')],
          }
        default:
          return {
            subtitle: translate('yubikey_error_dismissed'),
            tips: [translate('yubikey_error_tip_reauth')],
            errorReference: supportReferenceFor(walletError),
          }
      }
    }

    switch (passkeyError?.code) {
      case PasskeyErrorCodes.INVALID_DEVICE:
        return {
          subtitle: translate('yubikey_error_invalid_device'),
          tips: [translate('yubikey_error_tip_invalid_device')],
        }
      case PasskeyErrorCodes.FAILED_WRITE:
        return {
          subtitle: translate('yubikey_error_invalid_firmware', {
            checkFirmwareLink: DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_FIRMWARE,
          }),
          tips: [translate('yubikey_error_tip_invalid_firmware')],
        }
      case PasskeyErrorCodes.DUPLICATE:
        return {
          subtitle: translate('yubikey_error_duplicate'),
          tips: [translate('yubikey_error_tip_duplicate')],
        }
      default:
        return {
          subtitle: translate('yubikey_error_dismissed'),
          errorReference: supportReferenceFor(passkeyError ?? phraseError),
          tips:
            phraseError?.message ===
            'Failed to read seed phrase from passkey prompt'
              ? []
              : [
                  translate('yubikey_error_tip_firmware_short', {
                    checkFirmwareLink:
                      DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_FIRMWARE,
                  }),
                  translate('yubikey_error_tip_failed_write'),
                ],
        }
    }
  }, [passkeyError, walletError, translate, phraseError])

  const onTryAgain = useCallback(async () => {
    if (passkeyError !== null) {
      resetErrors()
      await onForward(DEVICE_STEPS.YUBIKEY_COPY_EXPORT_START)
      return
    }

    if (walletError !== null) {
      resetErrors()
      await onForward(DEVICE_STEPS.YUBIKEY_INTERACT_WALLET)
    }

    await onForward(DEVICE_STEPS.YUBIKEY_COPY_EXPORT_START)
  }, [passkeyError, onForward, resetErrors, walletError])

  return (
    <DeviceConfirmation
      errorReference={errorReference}
      key={DEVICE_STEPS.YUBIKEY_ERROR}
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
        <TroubleshootingFooter
          tips={tips}
          supportInfo={translate('yubikey_error_copy_footer_setup', {
            troubleshootingLink: DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_COPY,
            supportLink: LINK.YUBIKEY_SETUP_SUPPORT,
          })}
        />
      </Fragment>
    </DeviceConfirmation>
  )
}
