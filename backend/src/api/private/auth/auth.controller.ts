/*
 * SPDX-FileCopyrightText: 2024 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
  Redirect,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';

import { LdapLoginDto } from '../../../identity/ldap/ldap-login.dto';
import { LdapAuthGuard } from '../../../identity/ldap/ldap.strategy';
import { LocalIdentityService } from '../../../identity/local/local-identity.service';
import { LocalAuthGuard } from '../../../identity/local/local.strategy';
import { LoginDto } from '../../../identity/local/login.dto';
import { RegisterDto } from '../../../identity/local/register.dto';
import { UpdatePasswordDto } from '../../../identity/local/update-password.dto';
import { OidcService } from '../../../identity/oidc/oidc.service';
import { ProviderType } from '../../../identity/provider-type.enum';
import {
  RequestWithSession,
  SessionGuard,
} from '../../../identity/session.guard';
import { ConsoleLoggerService } from '../../../logger/console-logger.service';
import { FullUserInfoDto } from '../../../users/user-info.dto';
import { User } from '../../../users/user.entity';
import { UsersService } from '../../../users/users.service';
import { makeUsernameLowercase } from '../../../utils/username';
import { LoginEnabledGuard } from '../../utils/login-enabled.guard';
import { OpenApi } from '../../utils/openapi.decorator';
import { RegistrationEnabledGuard } from '../../utils/registration-enabled.guard';
import { RequestUser } from '../../utils/request-user.decorator';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly logger: ConsoleLoggerService,
    private usersService: UsersService,
    private localIdentityService: LocalIdentityService,
    private oidcService: OidcService,
  ) {
    this.logger.setContext(AuthController.name);
  }

  @UseGuards(RegistrationEnabledGuard)
  @Post('local')
  @OpenApi(201, 400, 403, 409)
  async registerUser(
    @Req() request: RequestWithSession,
    @Body() registerDto: RegisterDto,
  ): Promise<void> {
    await this.localIdentityService.checkPasswordStrength(registerDto.password);
    const user = await this.usersService.createUser(
      registerDto.username,
      registerDto.displayName,
    );
    await this.localIdentityService.createLocalIdentity(
      user,
      registerDto.password,
    );
    request.session.username = registerDto.username;
    request.session.authProviderType = ProviderType.LOCAL;
  }

  @UseGuards(LoginEnabledGuard, SessionGuard)
  @Put('local')
  @OpenApi(200, 400, 401)
  async updatePassword(
    @RequestUser() user: User,
    @Body() changePasswordDto: UpdatePasswordDto,
  ): Promise<void> {
    await this.localIdentityService.checkLocalPassword(
      user,
      changePasswordDto.currentPassword,
    );
    await this.localIdentityService.updateLocalPassword(
      user,
      changePasswordDto.newPassword,
    );
  }

  @UseGuards(LoginEnabledGuard, LocalAuthGuard)
  @Post('local/login')
  @OpenApi(201, 400, 401)
  login(
    @Req()
    request: RequestWithSession,
    @Body() loginDto: LoginDto,
  ): void {
    // There is no further testing needed as we only get to this point if LocalAuthGuard was successful
    request.session.username = loginDto.username;
    request.session.authProviderType = ProviderType.LOCAL;
  }

  @UseGuards(LdapAuthGuard)
  @Post('ldap/:ldapIdentifier')
  @OpenApi(201, 400, 401)
  loginWithLdap(
    @Req()
    request: RequestWithSession,
    @Param('ldapIdentifier') ldapIdentifier: string,
    @Body() loginDto: LdapLoginDto,
  ): void {
    // There is no further testing needed as we only get to this point if LdapAuthGuard was successful
    request.session.username = makeUsernameLowercase(loginDto.username);
    request.session.authProviderType = ProviderType.LDAP;
    request.session.authProviderIdentifier = ldapIdentifier;
  }

  @Get('oidc/:oidcIdentifier')
  @Redirect()
  @OpenApi(201, 400, 401)
  loginWithOpenIdConnect(
    @Req() request: RequestWithSession,
    @Param('oidcIdentifier') oidcIdentifier: string,
  ): { url: string } {
    const code = this.oidcService.generateCode();
    request.session.oidcLoginCode = code;
    const authorizationUrl = this.oidcService.getAuthorizationUrl(
      oidcIdentifier,
      code,
    );
    return { url: authorizationUrl };
  }

  @Get('oidc/:oidcIdentifier/callback')
  @Redirect()
  @OpenApi(201, 400, 401)
  async callback(
    @Param('oidcIdentifier') oidcIdentifier: string,
    @Req() request: RequestWithSession,
  ): Promise<{ url: string }> {
    try {
      const userInfo = await this.oidcService.extractUserInfoFromCallback(
        oidcIdentifier,
        request,
      );
      request.session.authProviderType = ProviderType.OIDC;
      request.session.authProviderIdentifier = oidcIdentifier;
      const identity = await this.oidcService.getExistingOidcIdentity(
        oidcIdentifier,
        userInfo,
      );
      if (identity) {
        const user = await identity.user;
        request.session.username = user.username;
        return { url: '/' };
      } else {
        request.session.newUserData = userInfo;
        return { url: '/new-user' };
      }
    } catch (error) {
      this.logger.log(
        'Error during OIDC callback:' + String(error),
        'callback',
      );
      throw new UnauthorizedException();
    }
  }

  @UseGuards(SessionGuard)
  @Delete('logout')
  @OpenApi(200, 400, 401)
  logout(@Req() request: RequestWithSession): { redirect: string } {
    let logoutUrl: string | null = null;
    if (request.session.authProviderType === ProviderType.OIDC) {
      logoutUrl = this.oidcService.getLogoutUrl(request);
    }
    request.session.destroy((err) => {
      if (err) {
        this.logger.error(
          'Error during logout:' + String(err),
          undefined,
          'logout',
        );
        throw new BadRequestException('Unable to log out');
      }
    });
    return {
      redirect: logoutUrl || '/',
    };
  }

  @UseGuards(SessionGuard)
  @Get('pending-user')
  @OpenApi(200, 400)
  getPendingUserData(
    @Req() request: RequestWithSession,
  ): Partial<FullUserInfoDto> {
    if (!request.session.newUserData) {
      throw new BadRequestException('No pending user data');
    }
    return {
      username: (
        request.session.newUserData.preferred_username ||
        request.session.newUserData.sub
      ).toLowerCase() as Lowercase<string>,
      displayName: request.session.newUserData.name,
      photoUrl: request.session.newUserData.picture,
      email: request.session.newUserData.email,
    };
  }

  @UseGuards(SessionGuard)
  @Delete('pending-user')
  @OpenApi(204, 400)
  deletePendingUserData(@Req() request: RequestWithSession): void {
    request.session.newUserData = undefined;
    request.session.authProviderIdentifier = undefined;
    request.session.authProviderType = undefined;
  }
}
