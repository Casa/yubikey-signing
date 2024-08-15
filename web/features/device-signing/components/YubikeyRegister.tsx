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
import { Device } from 'src/constants/device'
import LINK from 'src/constants/link'
import {
  DefaultButton,
  SecondaryButton,
} from 'src/features/device-signing/components/Buttons'
import DeviceConfirmation from 'src/features/device-signing/components/DeviceConfirmation'
import {
  InstructionsBanner,
  TroubleshootingFooter,
  WarningBanner,
} from 'src/features/device-signing/components/HelpBanners'
import PasskeyLoading from 'src/features/device-signing/components/PasskeyLoading'
import RequireChrome from 'src/features/device-signing/components/RequireChrome'
import YubikeyExport, {
  CopyLocation,
} from 'src/features/device-signing/components/YubikeyExport'
import * as DEVICE_LINKS from 'src/features/device-signing/constants/link'
import { DEVICE_STEPS } from 'src/features/device-signing/constants/steps'
import useDeviceNavigation from 'src/features/device-signing/hooks/useDeviceNavigation'
import {
  WebWalletProvider,
  useWebWallet,
} from 'src/features/device-signing/hooks/useWebWallet'
import useFeatureFlags from 'src/hooks/useFeatureFlags'
import useTranslate from 'src/hooks/useTranslate'
import { ReactComponent as AlertCircleThin } from 'src/images/alert-circle-thin-icon.svg'
import { ReactComponent as CheckmarkCircleThin } from 'src/images/checkmark-circle-thin-icon.svg'
import { ReactComponent as YubikeyIcon } from 'src/images/yubikey-icon.svg'

/**
 * Controls display for a hardware wallet setup process using a passkey device. This must
 * be kept distinct from the Ledger and Trezor (and other hardware wallet) setup processes
 * because of server option calls, and error handling about passkey-specific interactions
 * issues.
 */
export function YubikeySetup() {
  const { step } = useDeviceNavigation()

  switch (step) {
    case DEVICE_STEPS.YUBIKEY_START:
      return <YubikeySetupStart />
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
    case DEVICE_STEPS.YUBIKEY_ERROR:
    default:
      return <YubikeyError />
  }
}

// Shows the initial screen for setting up a Yubikey device
export function YubikeySetupStart() {
  const { translate } = useTranslate()

  const { passkeyError } = useWebWallet()
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
      title={translate('yubikey_setup_title')}
      subTitle={translate('yubikey_setup_subtitle')}
      primaryButton={
        <DefaultButton onClick={onContinue}>
          {translate('continue')}
        </DefaultButton>
      }
      secondaryButton={
        <SecondaryButton
          onClick={() => onForward(DEVICE_STEPS.DEVICE_SELECTION)}
        >
          {translate('choose_different_device')}
        </SecondaryButton>
      }
    >
      <>
        <Spacer unit={12} />
        <WarningBanner
          warningLabel={translate('important')}
          warnings={[
            translate('yubikey_setup_tip', {
              checkFirmwareLink: DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_FIRMWARE,
            }),
            <CopyLocation />,
          ]}
        />
      </>
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
        <DefaultButton onClick={onContinue}>
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
  const { xPub, createWallet, walletError, deviceUpdateLoading } =
    useWebWallet()

  const [passkeyPrompted, setPasskeyPrompted] = useState(false)
  const [minimumTimePassed, setMinimumTimePassed] =
    useState<boolean | null>(null)
  const timerRef = useRef<number | null>(null)

  useEffect(() => {
    if (passkeyPrompted === true) {
      return
    }

    setPasskeyPrompted(true)
    void createWallet()
  }, [passkeyPrompted, createWallet])

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
        title={translate('yubikey_reauth_loading_title')}
        interaction={<SpinningLoader size={45} color={COLOR.PURPLE_01} />}
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
  const { featureFlags } = useFeatureFlags()
  const { onForward } = useDeviceNavigation()

  if (featureFlags.enableYubikeySeedExport) {
    const onExport = () => {
      void onForward(DEVICE_STEPS.YUBIKEY_EXPORT_START)
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
        title={translate('yubikey_setup_success_title')}
        subTitle={translate('yubikey_setup_success_subtitle')}
        warnings={[<SeedWarning />]}
        primaryButton={
          <DefaultButton onClick={onExport}>
            {translate('yubikey_setup_success_cta_export')}
          </DefaultButton>
        }
        secondaryButton={
          <SecondaryButton onClick={onSkip}>
            {translate('yubikey_setup_success_cta_skip')}
          </SecondaryButton>
        }
      />
    )
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
      subTitle={translate('yubikey_setup_success_subtitle_close')}
    />
  )
}

/**
 * A general error view to handle a parsed Passkey error to
 * show the user a message and a call to action to try again
 */
function YubikeyError() {
  const { passkeyError, walletError, resetErrors } = useWebWallet()
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()

  const { subtitle, tips } = useMemo(() => {
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
          tips: [
            translate('yubikey_error_tip_firmware_short', {
              checkFirmwareLink: DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_FIRMWARE,
            }),
            translate('yubikey_error_tip_failed_write'),
          ],
        }
    }
  }, [passkeyError, walletError, translate])

  const onTryAgain = useCallback(async () => {
    if (passkeyError !== null) {
      resetErrors()
      await onForward(DEVICE_STEPS.YUBIKEY_INTERACT_PASSKEY)
      return
    }

    if (walletError !== null) {
      resetErrors()
      await onForward(DEVICE_STEPS.YUBIKEY_INTERACT_WALLET)
    }
  }, [passkeyError, onForward, resetErrors, walletError])

  return (
    <DeviceConfirmation
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
        <DefaultButton onClick={onTryAgain}>
          {translate('try_again')}
        </DefaultButton>
      }
    >
      <Fragment>
        <Spacer unit={8} />
        <TroubleshootingFooter
          tips={tips}
          supportInfo={translate('yubikey_error_footer_setup', {
            troubleshootingLink: DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_SETUP,
            supportLink: LINK.YUBIKEY_SETUP_SUPPORT,
          })}
        />
      </Fragment>
    </DeviceConfirmation>
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

// The provider-wrapped controller of all Yubikey register steps
export default function YubikeyRegister({ device }: { device: Device }) {
  return (
    <WebWalletProvider device={device}>
      <section
        css={css`
          max-width: 620px;
        `}
      >
        <RequireChrome>
          <YubikeySetup />
        </RequireChrome>
      </section>
    </WebWalletProvider>
  )
}

export const YUBIKEY_EXPORT_STEPS = [
  DEVICE_STEPS.YUBIKEY_EXPORT_START,
  DEVICE_STEPS.YUBIKEY_EXPORT_LOAD,
  DEVICE_STEPS.YUBIKEY_EXPORT_VIEW,
  DEVICE_STEPS.YUBIKEY_EXPORT_TEST,
  DEVICE_STEPS.YUBIKEY_EXPORT_SUCCESS,
  DEVICE_STEPS.YUBIKEY_EXPORT_ERROR,
]

export const YUBIKEY_SETUP_STEPS = [
  DEVICE_STEPS.YUBIKEY_START,
  DEVICE_STEPS.YUBIKEY_INTERACT_PASSKEY,
  DEVICE_STEPS.YUBIKEY_SETUP_CONFIRM,
  DEVICE_STEPS.YUBIKEY_INTERACT_WALLET,
  DEVICE_STEPS.YUBIKEY_SUCCESS,
  DEVICE_STEPS.YUBIKEY_ERROR,
  ...YUBIKEY_EXPORT_STEPS,
]
