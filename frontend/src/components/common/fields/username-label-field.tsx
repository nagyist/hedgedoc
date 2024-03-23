/*
 * SPDX-FileCopyrightText: 2022 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import type { UsernameFieldProps } from './username-field'
import { UsernameField } from './username-field'
import React, { useState } from 'react'
import { Form } from 'react-bootstrap'
import { Trans, useTranslation } from 'react-i18next'
import { useDebounce } from 'react-use'
import { checkUsernameAvailable } from '../../../api/auth'
import { Logger } from '../../../utils/logger'

const logger = new Logger('UsernameLabelField')

/**
 * Wraps and contains label and info for UsernameField
 *
 * @param onChange Callback that is called when the entered username changes.
 * @param value The currently entered username.
 */
export const UsernameLabelField: React.FC<UsernameFieldProps> = ({ value, ...props }) => {
  useTranslation()
  const [usernameValid, setUsernameValid] = useState(false)
  const [usernameInvalid, setUsernameInvalid] = useState(false)

  useDebounce(
    () => {
      if (value === '') {
        setUsernameValid(false)
        setUsernameInvalid(false)
        return
      }
      if (!/^[a-zA-Z0-9_.]{3,64}$/.test(value)) {
        setUsernameValid(false)
        setUsernameInvalid(true)
        return
      }
      checkUsernameAvailable(value)
        .then((available) => {
          setUsernameValid(available)
          setUsernameInvalid(!available)
        })
        .catch((error) => {
          logger.error('Failed to check username availability', error)
          setUsernameValid(false)
          setUsernameInvalid(false)
        })
    },
    500,
    [value]
  )

  return (
    <Form.Group>
      <Form.Label>
        <Trans i18nKey='login.auth.username' />
      </Form.Label>
      <UsernameField value={value} {...props} isInvalid={usernameInvalid} isValid={usernameValid} />
      <Form.Text>
        <Trans i18nKey='login.register.usernameInfo' />
      </Form.Text>
    </Form.Group>
  )
}
