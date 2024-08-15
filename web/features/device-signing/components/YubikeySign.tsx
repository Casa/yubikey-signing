import { PasskeyErrorCodes } from '@casa/device-signing/src/utils/passkeyUtils'
import { css } from '@emotion/react'
import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'

import Spacer from 'src/components/Spacer'
import COLOR from 'src/constants/color'
import LINK from 'src/constants/link'
import { Signature } from 'src/constants/signature'
import {
  DefaultButton,
  SecondaryButton,
} from 'src/features/device-signing/components/Buttons'
import DeviceConfirmation from 'src/features/device-signing/components/DeviceConfirmation'
import { TroubleshootingFooter } from 'src/features/device-signing/components/HelpBanners'
import PasskeyLoading from 'src/features/device-signing/components/PasskeyLoading'
import RequireChrome from 'src/features/device-signing/components/RequireChrome'
import * as DEVICE_LINKS from 'src/features/device-signing/constants/link'
import { DEVICE_STEPS } from 'src/features/device-signing/constants/steps'
import useDeviceNavigation from 'src/features/device-signing/hooks/useDeviceNavigation'
import {
  TransactionInputs,
  WebWalletProvider,
  useWebWallet,
} from 'src/features/device-signing/hooks/useWebWallet'
import useTranslate from 'src/hooks/useTranslate'
import { ReactComponent as AlertCircleThin } from 'src/images/alert-circle-thin-icon.svg'
import { ReactComponent as CheckmarkCircleThin } from 'src/images/checkmark-circle-thin-icon.svg'
import { ReactComponent as YubikeyIcon } from 'src/images/yubikey-icon.svg'

/**
 * Controls display for a hardware wallet SIGN process using a passkey device. This must
 * be kept distinct from the Ledger and Trezor (and other hardware wallet) processes
 * because of server option calls, and error handling about passkey-specific interactions
 * issues.
 *
 * This component is valid for both health checks and transaction signing.
 */
function YubikeySignFlow() {
  const { step } = useDeviceNavigation()

  switch (step) {
    case DEVICE_STEPS.YUBIKEY_START:
      return <YubikeyStart />
    case DEVICE_STEPS.YUBIKEY_SIGN_LOADING:
    case DEVICE_STEPS.YUBIKEY_HEALTH_LOADING:
      return <YubikeySignLoading />
    case DEVICE_STEPS.YUBIKEY_SIGN_SUCCESS:
    case DEVICE_STEPS.YUBIKEY_HEALTH_SUCCESS:
      return <YubikeySignSuccess />
    case DEVICE_STEPS.YUBIKEY_SIGN_ERROR:
    case DEVICE_STEPS.YUBIKEY_HEALTH_ERROR:
    default:
      return <YubikeySignError />
  }
}

// Shows the initial screen for signing with a Yubikey device
export function YubikeyStart() {
  const { translate } = useTranslate()

  const { signError, isHealthCheck } = useWebWallet()
  const { onForward } = useDeviceNavigation()

  const nextStep = isHealthCheck
    ? DEVICE_STEPS.YUBIKEY_HEALTH_LOADING
    : DEVICE_STEPS.YUBIKEY_SIGN_LOADING

  const errorStep = isHealthCheck
    ? DEVICE_STEPS.YUBIKEY_HEALTH_ERROR
    : DEVICE_STEPS.YUBIKEY_SIGN_ERROR

  const onContinue = () => {
    void onForward(nextStep)
  }

  useEffect(() => {
    if (signError != null) {
      void onForward(errorStep)
    }
  }, [signError, onForward, errorStep])

  return (
    <DeviceConfirmation
      titleIcon={<YubikeyIcon />}
      key={DEVICE_STEPS.YUBIKEY_START}
      title={translate('yubikey_sign_start_title')}
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
    />
  )
}

/**
 * Shows the loading screen for signing with a Yubikey device while the
 * user submits a passkey authentication response
 */
function YubikeySignLoading() {
  const { translate } = useTranslate()
  const { onForward } = useDeviceNavigation()
  const {
    signature,
    isHealthCheck,
    signHealthCheck,
    signTransaction,
    signatureResult,
    signError,
  } = useWebWallet()

  const [passkeyPrompted, setPasskeyPrompted] = useState(false)

  const nextStep = useMemo(() => {
    if (signature?.recoveryDataReset?.dataType === 'PASSWORD') {
      return DEVICE_STEPS.PASSWORD_RESET
    }

    if (isHealthCheck) {
      return DEVICE_STEPS.YUBIKEY_HEALTH_SUCCESS
    }

    return DEVICE_STEPS.YUBIKEY_SIGN_SUCCESS
  }, [isHealthCheck, signature])

  const { onLoad, subtitle, errorStep } = useMemo(() => {
    if (isHealthCheck) {
      return {
        onLoad: signHealthCheck,
        subtitle: translate('yubikey_health_loading_subtitle'),
        errorStep: DEVICE_STEPS.YUBIKEY_HEALTH_ERROR,
      }
    }

    return {
      onLoad: signTransaction,
      subtitle: translate('yubikey_sign_loading_subtitle'),
      errorStep: DEVICE_STEPS.YUBIKEY_SIGN_ERROR,
    }
  }, [isHealthCheck, signHealthCheck, signTransaction, translate])

  useEffect(() => {
    if (passkeyPrompted === true) {
      return
    }

    setPasskeyPrompted(true)
    void onLoad()
  }, [onLoad, passkeyPrompted])

  useEffect(() => {
    const isSuccessful = signatureResult != null && signError == null

    if (isSuccessful === true) {
      void onForward(nextStep)
      return
    }

    if (signError != null) {
      void onForward(errorStep)
      return
    }
  }, [signatureResult, signError, nextStep, errorStep, onForward])

  return (
    <PasskeyLoading
      key={DEVICE_STEPS.YUBIKEY_INTERACT_PASSKEY}
      subTitle={subtitle}
      warnings={[
        translate('yubikey_warning_password_manager'),
        translate('yubikey_warning_prompt_selection'),
      ]}
    />
  )
}

// Success state for the Yubikey signing process
function YubikeySignSuccess() {
  const { translate } = useTranslate()
  const { isHealthCheck } = useWebWallet()

  const { title, subtitle } = isHealthCheck
    ? {
        title: translate('yubikey_health_success_title'),
        subtitle: translate('yubikey_health_success_subtitle'),
      }
    : {
        title: translate('yubikey_sign_success_title'),
        subtitle: translate('yubikey_sign_success_subtitle'),
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
      title={title}
      subTitle={subtitle}
    />
  )
}

// Error handling for the Yubikey signing process
function YubikeySignError() {
  const { signError, resetErrors, isHealthCheck } = useWebWallet()
  const { translate, translateWithFallback } = useTranslate()
  const { onForward } = useDeviceNavigation()

  const onTryAgain = useCallback(async () => {
    if (signError !== null) {
      resetErrors()

      if (isHealthCheck) {
        await onForward(DEVICE_STEPS.YUBIKEY_HEALTH_LOADING)
        return
      }

      await onForward(DEVICE_STEPS.YUBIKEY_SIGN_LOADING)
    }
  }, [signError, onForward, resetErrors, isHealthCheck])

  const subtitle = useMemo(() => {
    if (signError?.code === PasskeyErrorCodes.FAILED_READ) {
      return translate('yubikey_error_wrong_yubikey')
    }

    if (signError?.code === PasskeyErrorCodes.INVALID_SUBMISSION) {
      /**
       * Invalid submission errors may be caused by a variety of reasons,
       * Some API error codes are valid translation keys. If the error code
       * is not a valid translation key, default to a generic error message.
       *
       * This intentionally avoids use of useDeviceError as it checks for
       * complex string-matching values designed for hardware wallet errors
       * that are not inclusive of all possible passkey errors.
       */
      return translateWithFallback(
        (signError.data as { code: unknown })?.code,
        'yubikey_error_correct_device',
      )
    }

    return translate('yubikey_error_dismissed')
  }, [signError, translate, translateWithFallback])

  const supportInfo =
    isHealthCheck === true
      ? translate('yubikey_error_footer_health', {
          troubleshootingLink: DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_HEALTH_CHECK,
          supportLink: LINK.YUBIKEY_HEALTH_SUPPORT,
        })
      : translate('yubikey_error_footer_sign', {
          troubleshootingLink: DEVICE_LINKS.TROUBLESHOOT_YUBIKEY_TRANSACTION,
          supportLink: LINK.YUBIKEY_TRANSACTION_SUPPORT,
        })

  const tips =
    isHealthCheck === true
      ? [translate('yubikey_error_correct_device')]
      : [
          translate('yubikey_error_correct_device'),
          translate('yubikey_error_key_replacement'),
        ]

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
        <TroubleshootingFooter tips={tips} supportInfo={supportInfo} />
      </Fragment>
    </DeviceConfirmation>
  )
}

// Context-wrapped component for the Yubikey signing process
export default function YubikeySign({
  isHealthCheck,
  isTransaction,
  signature,
  transactionInputs,
}: {
  signature: Signature
  transactionInputs?: TransactionInputs
  isHealthCheck?: boolean
  isTransaction?: boolean
}) {
  return (
    <WebWalletProvider
      signature={signature}
      isHealthCheck={isHealthCheck}
      isTransaction={isTransaction}
      transactionInputs={transactionInputs}
    >
      <section
        css={css`
          max-width: 700px;
        `}
      >
        <RequireChrome>
          <YubikeySignFlow />
        </RequireChrome>
      </section>
    </WebWalletProvider>
  )
}
