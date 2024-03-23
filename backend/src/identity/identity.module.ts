/*
 * SPDX-FileCopyrightText: 2024 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';

import { LoggerModule } from '../logger/logger.module';
import { User } from '../users/user.entity';
import { UsersModule } from '../users/users.module';
import { Identity } from './identity.entity';
import { IdentityService } from './identity.service';
import { LdapAuthGuard, LdapStrategy } from './ldap/ldap.strategy';
import { LocalIdentityService } from './local/local-identity.service';
import { LocalAuthGuard, LocalStrategy } from './local/local.strategy';
import { OidcService } from './oidc/oidc.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([Identity, User]),
    UsersModule,
    PassportModule.register({ session: true }),
    LoggerModule,
  ],
  controllers: [],
  providers: [
    IdentityService,
    LocalIdentityService,
    LocalStrategy,
    LdapStrategy,
    OidcService,
    LdapAuthGuard,
    LocalAuthGuard,
  ],
  exports: [
    IdentityService,
    LocalStrategy,
    LdapStrategy,
    LocalIdentityService,
    OidcService,
  ],
})
export class IdentityModule {}
