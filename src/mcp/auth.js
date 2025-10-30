import * as env from './env.js';
import {ApiClient, VerifyAccessTokenError} from "@auth0/auth0-api-js";
import {InvalidTokenError,} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import {createLogger} from '../utils/logger.js';

const log = createLogger('mcp-auth');

// Resource server's OAuth 2.0 client for token verification and exchange
// Configured with the MCP resource server's audience
const apiClient = env.AUTH_ENABLED ? new ApiClient({
  domain: env.AUTH0_DOMAIN,
  audience: env.MCP_AUTH0_AUDIENCE,
  ...(env.CTE_ENABLED && {
    clientId: env.MCP_AUTH0_CLIENT_ID,
    clientSecret: env.MCP_AUTH0_CLIENT_SECRET,
  }),
}) : null;

// See https://auth0.com/docs/authenticate/custom-token-exchange
export async function exchangeCustomToken(subjectToken) {
    if (!env.CTE_ENABLED) throw new Error('cte not configured');

    // Use the resource server's OAuth 2.0 client to exchange tokens
    // The 'audience' parameter specifies the target audience for the exchanged token
    // SDK returns: { accessToken, expiresAt, scope?, idToken?, refreshToken?, ... }
    return await apiClient.getTokenByExchangeProfile(subjectToken, {
      subjectTokenType: env.MCP_AUTH0_SUBJECT_TOKEN_TYPE,
      audience: env.API_AUTH0_AUDIENCE, // Target audience for the exchanged token
      ...(env.MCP_AUTH0_EXCHANGE_SCOPE && { scope: env.MCP_AUTH0_EXCHANGE_SCOPE }),
    });
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

export const createMcpAuthFunction = () => {
  return async (request, bearer) => {
    if (!bearer) {
      log.error('MCP Auth failed: Missing bearer token');
      throw new InvalidTokenError("Missing authorization token");
    }

    // Debug token format
    log.log('Token received, length:', bearer.length);
    log.log('Token format check - parts:', bearer.split('.').length, 'expected: 3 for JWT');

    try {
      log.log('Attempting token verification with Auth0...');
      const decoded = await apiClient.verifyAccessToken({
        accessToken: bearer,
      });

      log.log('Token verification successful, decoded claims:', {
        sub: decoded.sub,
        client_id: decoded.client_id,
        azp: decoded.azp,
        aud: decoded.aud,
        scope: decoded.scope,
        exp: decoded.exp
      });

      if (!isNonEmptyString(decoded.sub)) {
        log.error('MCP Auth failed: Token missing required subject (sub) claim');
        throw new InvalidTokenError("Token is missing required subject (sub) claim");
      }

      let clientId = null;
      if (isNonEmptyString(decoded.client_id)) {
        clientId = decoded.client_id;
      } else if (isNonEmptyString(decoded.azp)) {
        clientId = decoded.azp;
      }

      if (!clientId) {
        log.error('MCP Auth failed: Token missing required client identification (client_id or azp claim)');
        throw new InvalidTokenError("Token is missing required client identification (client_id or azp claim)");
      }

      const session = {
        token: bearer,
        clientId,
        scopes:
          typeof decoded.scope === "string"
            ? decoded.scope.split(" ").filter(Boolean)
            : [],
        ...(decoded.exp && { expiresAt: decoded.exp }),
        extra: {
          sub: decoded.sub,
          ...(isNonEmptyString(decoded.client_id) && {
            client_id: decoded.client_id,
          }),
          ...(isNonEmptyString(decoded.azp) && { azp: decoded.azp }),
          ...(isNonEmptyString(decoded.name) && { name: decoded.name }),
          ...(isNonEmptyString(decoded.email) && { email: decoded.email }),
        },
      };

      log.log('Session created successfully for user:', decoded.sub);
      return session;
    } catch (error) {
      if (error instanceof VerifyAccessTokenError) {
        log.error('MCP Auth failed: Token verification error:', error.message);
        log.error('VerifyAccessTokenError details:', error);
        throw new InvalidTokenError(`Token verification failed: ${error.message}`);
      } else if (error instanceof InvalidTokenError) {
        // Re-throw InvalidTokenError as-is (already logged above)
        throw error;
      } else {
        log.error('MCP Auth failed: Unexpected error:', error.message);
        log.error('Full error object:', error);
        throw new InvalidTokenError("Authentication failed due to internal error");
      }
    }
  };
};
