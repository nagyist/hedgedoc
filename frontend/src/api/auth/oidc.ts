/*
 * SPDX-FileCopyrightText: 2024 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import type { FullUserInfo } from '../users/types'
import { GetApiRequestBuilder } from '../common/api-request-builder/get-api-request-builder'
import { DeleteApiRequestBuilder } from '../common/api-request-builder/delete-api-request-builder'

export const getPendingUserInfo = async (): Promise<Partial<FullUserInfo>> => {
  const response = await new GetApiRequestBuilder<Partial<FullUserInfo>>('auth/pending-user').sendRequest()
  return response.asParsedJsonObject()
}

export const cancelPendingUser = async (): Promise<void> => {
  await new DeleteApiRequestBuilder<void>('auth/pending-user').sendRequest()
}
