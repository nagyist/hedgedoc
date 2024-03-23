/*
 * SPDX-FileCopyrightText: 2024 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { NotInDBError } from '../errors/errors';
import { ConsoleLoggerService } from '../logger/console-logger.service';
import { User } from '../users/user.entity';
import { Identity } from './identity.entity';
import { ProviderType } from './provider-type.enum';

@Injectable()
export class IdentityService {
  constructor(
    private readonly logger: ConsoleLoggerService,
    @InjectRepository(Identity)
    private identityRepository: Repository<Identity>,
  ) {
    this.logger.setContext(IdentityService.name);
  }

  /**
   * @async
   * Retrieve an identity by userId and providerType.
   * @param {string} userId - the userId of the wanted identity
   * @param {ProviderType} providerType - the providerType of the wanted identity
   * @param {string} providerIdentifier - optional name of the provider if multiple exist
   */
  async getIdentityFromUserIdAndProviderType(
    userId: string,
    providerType: ProviderType,
    providerIdentifier?: string,
  ): Promise<Identity> {
    const identity = await this.identityRepository.findOne({
      where: {
        providerUserId: userId,
        providerType,
        providerIdentifier,
      },
      relations: ['user'],
    });
    if (identity === null) {
      throw new NotInDBError(`Identity for user id '${userId}' not found`);
    }
    return identity;
  }

  /**
   * @async
   * Update the given Identity with the given information
   * @param {Identity} identity - the identity to update
   * @param {string | undefined} displayName - the displayName to update the user with
   * @param {string | undefined} email - the email to update the user with
   * @param {string | undefined} profilePicture - the profilePicture to update the user with
   */
  async updateIdentity(
    identity: Identity,
    displayName?: string,
    email?: string,
    profilePicture?: string,
  ): Promise<Identity> {
    if (identity.syncSource) {
      // The identity is the syncSource and the user should be changed accordingly
      const user = await identity.user;
      let shouldSave = false;
      if (displayName) {
        user.displayName = displayName;
        shouldSave = true;
      }
      if (email) {
        user.email = email;
        shouldSave = true;
      }
      if (profilePicture) {
        user.photo = profilePicture;
        shouldSave = true;
        // ToDo: handle LDAP images (https://github.com/hedgedoc/hedgedoc/issues/5032)
      }
      if (shouldSave) {
        identity.user = Promise.resolve(user);
        return await this.identityRepository.save(identity);
      }
    }
    return identity;
  }

  /**
   * @async
   * Create a new generic identity.
   * @param {User} user - the user the identity should be added to
   * @param {ProviderType} providerType - the providerType of the identity
   * @param {string} userId - the userId the identity should have
   * @return {Identity} the new local identity
   */
  async createIdentity(
    user: User,
    providerType: ProviderType,
    userId: string,
  ): Promise<Identity> {
    const identity = Identity.create(user, providerType, false);
    identity.providerUserId = userId;
    return await this.identityRepository.save(identity);
  }
}
