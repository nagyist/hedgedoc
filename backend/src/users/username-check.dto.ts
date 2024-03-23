/*
 * SPDX-FileCopyrightText: 2024 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import { IsBoolean, IsLowercase, IsString } from 'class-validator';

import { BaseDto } from '../utils/base.dto.';
import { Username } from '../utils/username';

export class UsernameCheckDto extends BaseDto {
  @IsString()
  @IsLowercase()
  username: Username;
}

export class UsernameCheckResponseDto extends BaseDto {
  @IsBoolean()
  usernameAvailable: boolean;
}
