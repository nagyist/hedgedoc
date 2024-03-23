/*
 * SPDX-FileCopyrightText: 2024 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import React, { useCallback, useEffect, useState } from 'react'
import { Button, Card, Form } from 'react-bootstrap'
import { Trans } from 'react-i18next'
import { useAsync } from 'react-use'
import { cancelPendingUser, getPendingUserInfo } from '../../../api/auth/oidc'
import { useRouter } from 'next/navigation'
import { useUiNotifications } from '../../notifications/ui-notification-boundary'
import { UsernameLabelField } from '../../common/fields/username-label-field'
import { DisplayNameField } from '../../common/fields/display-name-field'
import { ProfilePictureChoice, ProfilePictureSelectField } from '../../common/fields/profile-picture-select-field'
import { useOnInputChange } from '../../../hooks/common/use-on-input-change'

export const NewUserCard: React.FC = () => {
  const router = useRouter()
  const { showErrorNotification } = useUiNotifications()
  const { value, error, loading } = useAsync(getPendingUserInfo, [])
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [pictureChoice, setPictureChoice] = useState(ProfilePictureChoice.FALLBACK)

  const onChangeUsername = useOnInputChange(setUsername)
  const onChangeDisplayName = useOnInputChange(setDisplayName)

  // TODO Check if username editing is allowed

  const submitUserdata = useCallback(() => {
    console.log('Hooray, a new user!', username)
    // TODO Send to backend
  }, [username])

  const cancelUserCreation = useCallback(() => {
    cancelPendingUser()
      .catch(showErrorNotification('login.welcome.cancelError'))
      .finally(() => {
        router.push('/login')
      })
  }, [router])

  useEffect(() => {
    if (error) {
      showErrorNotification('login.welcome.error')(error)
      router.push('/login')
    }
  }, [error, router, showErrorNotification])

  useEffect(() => {
    if (!value) {
      return
    }
    setUsername(value.username ?? '')
    setDisplayName(value.displayName ?? '')
    if (value.photoUrl) {
      setPictureChoice(ProfilePictureChoice.PROVIDER)
    }
  }, [value])

  if (!value && !loading) {
    return null
  }

  return (
    <Card>
      <Card.Body>
        {loading && <p>Loading...</p>}
        <Card.Title>
          {displayName !== '' ? (
            <Trans i18nKey={'login.welcome.title'} values={{ name: displayName }} />
          ) : (
            <Trans i18nKey={'login.welcome.titleFallback'} />
          )}
        </Card.Title>
        <Trans i18nKey={'login.welcome.description'} />
        <hr />
        <Form onSubmit={submitUserdata} className={'d-flex flex-column gap-3'}>
          <DisplayNameField onChange={onChangeDisplayName} value={displayName} />
          <UsernameLabelField onChange={onChangeUsername} value={username} />
          <ProfilePictureSelectField
            onChange={setPictureChoice}
            value={pictureChoice}
            pictureUrl={value?.photoUrl}
            username={username}
          />
          <div className={'d-flex gap-3'}>
            <Button variant={'secondary'} type={'button'} className={'w-50'} onClick={cancelUserCreation}>
              <Trans i18nKey={'common.cancel'} />
            </Button>
            <Button variant={'success'} type={'submit'} className={'w-50'}>
              <Trans i18nKey={'common.continue'} />
            </Button>
          </div>
        </Form>
      </Card.Body>
    </Card>
  )
}
