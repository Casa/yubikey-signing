import { css } from '@emotion/react'
import React from 'react'

/**
 * Inline SVG icons used by the YubiKey seed-import flow. Extracted from
 * YubikeyImport.tsx because they're pure (no props, no state) and reused
 * across multiple step components. Keeping them in their own file makes
 * the main flow file smaller and easier to navigate.
 */

// Yellow info circle used as a warning bullet in the code-display,
// passkey-setup, and session-lost screens.
export function InfoCircleIcon(): React.ReactElement {
  return (
    <svg
      width='16'
      height='16'
      viewBox='0 0 16 16'
      fill='none'
      xmlns='http://www.w3.org/2000/svg'
      aria-hidden='true'
    >
      <path
        d='M8 1.33334C4.31814 1.33334 1.33334 4.31814 1.33334 8C1.33334 11.6819 4.31814 14.6667 8 14.6667C11.6819 14.6667 14.6667 11.6819 14.6667 8C14.6667 4.31814 11.6819 1.33334 8 1.33334ZM8 4.66668C8.36819 4.66668 8.66667 4.96516 8.66667 5.33334C8.66667 5.70153 8.36819 6.00001 8 6.00001C7.63181 6.00001 7.33334 5.70153 7.33334 5.33334C7.33334 4.96516 7.63181 4.66668 8 4.66668ZM8.66667 11.3333H7.33334V7.33334H8.66667V11.3333Z'
        fill='#FFD95E'
      />
    </svg>
  )
}

/**
 * 54px YubiKey hero icon. Wraps the existing rectangular yubikey-icon.svg in a
 * square frame for the seed-import layout.
 */
export function YubikeyHeroIcon(): React.ReactElement {
  return (
    <div
      css={css`
        width: 54px;
        height: 54px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      `}
    >
      <svg
        width='48'
        height='23'
        viewBox='0 0 54 26'
        fill='none'
        xmlns='http://www.w3.org/2000/svg'
        aria-hidden='true'
      >
        <path
          d='M39.9808 0.642578H1.55769C0.726923 0.642578 0 1.3695 0 2.20027V24.008C0 24.8387 0.726923 25.5657 1.55769 25.5657H39.9808C40.8115 25.5657 41.5385 24.8387 41.5385 24.008V2.20027C41.5385 1.3695 40.8115 0.642578 39.9808 0.642578ZM21.8077 19.4387C18.2769 19.4387 15.4731 16.6349 15.4731 13.1041C15.4731 9.57335 18.2769 6.7695 21.8077 6.7695C25.3385 6.7695 28.1423 9.57335 28.1423 13.1041C28.1423 16.6349 25.3385 19.4387 21.8077 19.4387Z'
          fill='white'
        />
        <path
          d='M21.8077 14.3507C22.4959 14.3507 23.0538 13.7928 23.0538 13.1046C23.0538 12.4163 22.4959 11.8584 21.8077 11.8584C21.1194 11.8584 20.5615 12.4163 20.5615 13.1046C20.5615 13.7928 21.1194 14.3507 21.8077 14.3507Z'
          fill='white'
        />
        <path
          d='M52.4425 4.69238H37.3848C36.5541 4.69238 35.8271 5.41931 35.8271 6.25008V19.7501C35.8271 20.5808 36.5541 21.3078 37.3848 21.3078H52.4425C53.2733 21.3078 54.0002 20.5808 54.0002 19.7501V6.25008C54.0002 5.41931 53.2733 4.69238 52.4425 4.69238ZM48.9118 8.84623C49.5348 8.84623 49.9502 9.26161 49.9502 9.88469V11.8578H41.5387V8.84623H48.9118ZM48.9118 17.1539H41.5387V14.3501H49.9502V16.1155C49.9502 16.7385 49.5348 17.1539 48.9118 17.1539Z'
          fill='white'
        />
      </svg>
    </div>
  )
}

// Yellow filled circle with exclamation, used inside the
// "Make sure you're in a private location" banner.
export function PrivacyAlertIcon(): React.ReactElement {
  return (
    <svg
      width='16'
      height='16'
      viewBox='0 0 16 16'
      fill='none'
      xmlns='http://www.w3.org/2000/svg'
      aria-hidden='true'
    >
      <circle cx='8' cy='8' r='8' fill='#F7BE00' />
      <path
        d='M8 4.5C8.41421 4.5 8.75 4.83579 8.75 5.25C8.75 5.66421 8.41421 6 8 6C7.58579 6 7.25 5.66421 7.25 5.25C7.25 4.83579 7.58579 4.5 8 4.5ZM7.25 7.5H8.75V11.5H7.25V7.5Z'
        fill='#1F1F1F'
      />
    </svg>
  )
}

/**
 * 54px yellow alert circle with white exclamation mark.
 */
export function WarningAlertIcon(): React.ReactElement {
  return (
    <svg
      width='54'
      height='54'
      viewBox='0 0 54 54'
      fill='none'
      xmlns='http://www.w3.org/2000/svg'
      aria-hidden='true'
    >
      <circle cx='27' cy='27' r='22.5' fill='#FFD95E' />
      <rect x='25' y='15' width='4' height='15' rx='2' fill='#11111F' />
      <circle cx='27' cy='37' r='2.5' fill='#11111F' />
    </svg>
  )
}

/**
 * 54px success check icon. Single evenodd path forms a filled cyan circle with
 * the checkmark carved out as negative space, transparent through to the
 * surface behind.
 */
export function SuccessCheckIcon(): React.ReactElement {
  return (
    <svg
      width='54'
      height='54'
      viewBox='-4.5 -4.5 54 54'
      fill='none'
      xmlns='http://www.w3.org/2000/svg'
      aria-hidden='true'
    >
      <path
        fillRule='evenodd'
        clipRule='evenodd'
        d='M22.5 45C34.9264 45 45 34.9264 45 22.5C45 10.0736 34.9264 0 22.5 0C10.0736 0 0 10.0736 0 22.5C0 34.9264 10.0736 45 22.5 45ZM18.2571 31.8125L34.4933 15.2811L32.3811 13.2067L18.2571 27.5875L12.6189 21.8467L10.5067 23.9211L18.2571 31.8125Z'
        fill='#7DE2E3'
      />
    </svg>
  )
}
