/*
 * SPDX-FileCopyrightText: 2024 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import {
  Inject,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { Client, generators, Issuer, UserinfoResponse } from 'openid-client';

import appConfiguration, { AppConfig } from '../../config/app.config';
import authConfiguration, {
  AuthConfig,
  OidcConfig,
} from '../../config/auth.config';
import { NotInDBError } from '../../errors/errors';
import { ConsoleLoggerService } from '../../logger/console-logger.service';
import { Identity } from '../identity.entity';
import { IdentityService } from '../identity.service';
import { ProviderType } from '../provider-type.enum';
import { RequestWithSession } from '../session.guard';

interface OidcClientConfigEntry {
  client: Client;
  issuer: Issuer;
  redirectUri: string;
}

@Injectable()
export class OidcService {
  private clientConfigs: Map<string, OidcClientConfigEntry> = new Map();

  constructor(
    private identityService: IdentityService,
    private logger: ConsoleLoggerService,
    @Inject(authConfiguration.KEY)
    private authConfig: AuthConfig,
    @Inject(appConfiguration.KEY)
    private appConfig: AppConfig,
  ) {
    this.initializeAllClients();
    // TODO The previous line should be regularly called again (@nestjs/cron?).
    // If the HedgeDoc instance is running for a long time,
    // the OIDC metadata or keys might change and the client needs to be reinitialized.
    this.logger.setContext(OidcService.name);
    this.logger.debug('OIDC service initialized', 'constructor');
  }

  /**
   * Initializes clients for all OIDC configurations by fetching their metadata and storing them in the clientConfigs map.
   */
  private initializeAllClients(): void {
    this.authConfig.oidc.forEach((oidcConfig) => {
      this.fetchClientConfig(oidcConfig)
        .then((config) => {
          this.clientConfigs.set(oidcConfig.identifier, config);
        })
        .catch((error) => {
          this.logger.error(
            `Failed to initialize OIDC client "${oidcConfig.identifier}": ${String(error)}`,
            undefined,
            'initializeClient',
          );
        });
    });
  }

  /**
   * Fetches the client and its config (issuer, metadata) for the given OIDC configuration.
   *
   * @param oidcConfig The OIDC configuration to fetch the client config for
   * @returns A promise that resolves to the client configuration.
   */
  private async fetchClientConfig(
    oidcConfig: OidcConfig,
  ): Promise<OidcClientConfigEntry> {
    const issuer = await Issuer.discover(oidcConfig.issuer);
    const redirectUri = `${this.appConfig.baseUrl}/api/private/auth/oidc/${oidcConfig.identifier}/callback`;
    const client = new issuer.Client({
      /* eslint-disable @typescript-eslint/naming-convention */
      client_id: oidcConfig.clientID,
      client_secret: oidcConfig.clientSecret,
      redirect_uris: [redirectUri],
      response_types: ['code'],
      /* eslint-enable @typescript-eslint/naming-convention */
    });
    return {
      client,
      issuer,
      redirectUri,
    };
  }

  /**
   * Generates a secure code verifier for the OIDC login.
   *
   * @returns The generated code verifier.
   */
  generateCode(): string {
    return generators.codeVerifier();
  }

  /**
   * Generates the authorization URL for the given OIDC identifier and code.
   *
   * @param oidcIdentifier The identifier of the OIDC configuration
   * @param code The code verifier generated for the login
   * @returns The generated authorization URL
   */
  getAuthorizationUrl(oidcIdentifier: string, code: string): string {
    const clientConfig = this.clientConfigs.get(oidcIdentifier);
    if (!clientConfig) {
      throw new NotFoundException('OIDC configuration not found');
    }
    const client = clientConfig.client;
    return client.authorizationUrl({
      scope: 'openid profile email',
      /* eslint-disable @typescript-eslint/naming-convention */
      code_challenge: generators.codeChallenge(code),
      code_challenge_method: 'S256',
      /* eslint-enable @typescript-eslint/naming-convention */
    });
  }

  /**
   * Extracts the user information from the callback and stores the access token in the session.
   *
   * @param oidcIdentifier The identifier of the OIDC configuration
   * @param request The request containing the session
   * @returns The user information response
   */
  async extractUserInfoFromCallback(
    oidcIdentifier: string,
    request: RequestWithSession,
  ): Promise<UserinfoResponse> {
    const clientConfig = this.clientConfigs.get(oidcIdentifier);
    if (!clientConfig) {
      throw new NotFoundException('OIDC configuration not found');
    }
    const client = clientConfig.client;
    const params = client.callbackParams(request);
    const code = request.session.oidcLoginCode;
    const tokenSet = await client.callback(clientConfig.redirectUri, params, {
      // eslint-disable-next-line @typescript-eslint/naming-convention
      code_verifier: code,
    });
    request.session.oidcLoginCode = undefined;
    request.session.oidcAccessToken = tokenSet.access_token;
    return await client.userinfo(tokenSet);
  }

  /**
   * Checks if an identity exists for a given OIDC user and returns it if it does.
   *
   * @param oidcIdentifier The identifier of the OIDC configuration
   * @param userInfo The user information response
   * @returns The identity if it exists, otherwise null
   */
  async getExistingOidcIdentity(
    oidcIdentifier: string,
    userInfo: UserinfoResponse,
  ): Promise<Identity | null> {
    const clientConfig = this.clientConfigs.get(oidcIdentifier);
    if (!clientConfig) {
      throw new NotFoundException('OIDC configuration not found');
    }
    try {
      return await this.identityService.getIdentityFromUserIdAndProviderType(
        userInfo.sub,
        ProviderType.OIDC,
        oidcIdentifier,
      );
    } catch (e) {
      if (e instanceof NotInDBError) {
        return null;
      } else {
        throw e;
      }
    }
  }

  /**
   * Returns the logout URL for the given request if the user is logged in with OIDC.
   *
   * @param request The request containing the session
   * @returns The logout URL if the user is logged in with OIDC, otherwise null
   */
  getLogoutUrl(request: RequestWithSession): string | null {
    const oidcIdentifier = request.session.authProviderIdentifier;
    if (!oidcIdentifier) {
      return null;
    }
    const clientConfig = this.clientConfigs.get(oidcIdentifier);
    if (!clientConfig) {
      throw new InternalServerErrorException('OIDC configuration not found');
    }
    const issuer = clientConfig.issuer;
    const endSessionEndpoint = issuer.metadata.end_session_endpoint;
    const idToken = request.session.oidcAccessToken;
    if (!endSessionEndpoint) {
      return null;
    }
    return `${endSessionEndpoint}?&post_logout_redirect_uri=${this.appConfig.baseUrl}${idToken ? `&id_token_hint=${idToken}` : ''}`;
  }
}
