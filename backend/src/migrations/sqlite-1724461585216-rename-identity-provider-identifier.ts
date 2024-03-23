/*
 * SPDX-FileCopyrightText: 2024 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import { MigrationInterface, QueryRunner } from 'typeorm';

export class RenameIdentityProviderIdentifier1724461585216
  implements MigrationInterface
{
  name = 'RenameIdentityProviderIdentifier1724461585216';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "identity" RENAME COLUMN "providerName" TO "providerIdentifier"`,
    );
    await queryRunner.query(
      `ALTER TABLE "identity" DROP COLUMN "oAuthAccessToken"`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "identity" RENAME COLUMN "providerIdentifier" TO "providerName"`,
    );
    await queryRunner.query(
      `ALTER TABLE "identity" ADD COLUMN "oAuthAccessToken" text`,
    );
  }
}
