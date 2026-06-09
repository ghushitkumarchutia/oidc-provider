import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { eq } from "drizzle-orm";
import { db } from "../../db/index.js";
import {
  clientsTable,
  authorizationCodesTable,
  refreshTokensTable,
  usersTable,
} from "../../db/schema.js";
import {
  generateIdToken,
  generateAccessToken,
  type IDTokenClaims,
  type AccessTokenClaims,
} from "../../common/token.js";

export async function authenticateClient(
  clientId: string,
  clientSecret: string,
) {
  const [client] = await db
    .select()
    .from(clientsTable)
    .where(eq(clientsTable.clientId, clientId))
    .limit(1);

  if (!client) return null;

  const match = await bcrypt.compare(clientSecret, client.clientSecret);
  if (!match) return null;

  return client;
}

function buildIdTokenClaims(
  user: {
    id: string;
    email: string;
    emailVerified: boolean;
    firstName: string | null;
    lastName: string | null;
    profileImageURL: string | null;
  },
  clientId: string,
  scope: string,
  nonce: string | null,
): IDTokenClaims {
  const ISSUER = `http://localhost:${process.env.PORT ?? 8080}`;
  const now = Math.floor(Date.now() / 1000);
  const scopes = scope.split(" ");

  const claims: IDTokenClaims = {
    iss: ISSUER,
    sub: user.id,
    aud: clientId,
    iat: now,
    exp: now + 3600,
  };

  if (nonce) claims.nonce = nonce;

  if (scopes.includes("email")) {
    claims.email = user.email;
    claims.email_verified = user.emailVerified;
  }

  if (scopes.includes("profile")) {
    claims.name = [user.firstName, user.lastName].filter(Boolean).join(" ");
    claims.given_name = user.firstName ?? undefined;
    claims.family_name = user.lastName ?? undefined;
    claims.picture = user.profileImageURL ?? undefined;
  }

  return claims;
}

async function issueRefreshToken(
  clientId: string,
  userId: string,
  scope: string,
  familyId?: string,
) {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const hashedToken = crypto
    .createHash("sha256")
    .update(rawToken)
    .digest("hex");

  await db.insert(refreshTokensTable).values({
    token: hashedToken,
    familyId: familyId || crypto.randomBytes(16).toString("hex"),
    clientId,
    userId,
    scope,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });

  return rawToken;
}

export async function exchangeAuthorizationCode(
  code: string,
  clientId: string,
  redirectUri: string,
  codeVerifier?: string,
) {
  const hashedCode = crypto.createHash("sha256").update(code).digest("hex");

  const [codeRow] = await db
    .select()
    .from(authorizationCodesTable)
    .where(eq(authorizationCodesTable.code, hashedCode))
    .limit(1);

  if (!codeRow) {
    return {
      error: "invalid_grant",
      error_description: "Invalid authorization code.",
    };
  }

  if (codeRow.used) {
    return {
      error: "invalid_grant",
      error_description: "Authorization code has already been used.",
    };
  }

  if (new Date() > codeRow.expiresAt) {
    return {
      error: "invalid_grant",
      error_description: "Authorization code has expired.",
    };
  }

  if (codeRow.clientId !== clientId) {
    return { error: "invalid_grant", error_description: "Client ID mismatch." };
  }

  if (codeRow.redirectUri !== redirectUri) {
    return {
      error: "invalid_grant",
      error_description: "Redirect URI mismatch.",
    };
  }

  if (codeRow.codeChallenge) {
    if (!codeVerifier) {
      return {
        error: "invalid_grant",
        error_description: "code_verifier is required.",
      };
    }

    const computed = crypto
      .createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");

    if (computed !== codeRow.codeChallenge) {
      return {
        error: "invalid_grant",
        error_description: "PKCE verification failed.",
      };
    }
  }

  await db
    .update(authorizationCodesTable)
    .set({ used: true })
    .where(eq(authorizationCodesTable.code, hashedCode));

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, codeRow.userId))
    .limit(1);

  if (!user) {
    return { error: "invalid_grant", error_description: "User not found." };
  }

  const idTokenClaims = buildIdTokenClaims(
    user,
    clientId,
    codeRow.scope,
    codeRow.nonce,
  );

  const accessTokenClaims: AccessTokenClaims = {
    iss: idTokenClaims.iss,
    sub: user.id,
    aud: clientId,
    iat: idTokenClaims.iat,
    exp: idTokenClaims.exp,
    scope: codeRow.scope,
  };

  const idToken = generateIdToken(idTokenClaims);
  const accessToken = generateAccessToken(accessTokenClaims);
  const refreshToken = await issueRefreshToken(
    clientId,
    user.id,
    codeRow.scope,
  );

  return {
    access_token: accessToken,
    id_token: idToken,
    refresh_token: refreshToken,
    token_type: "Bearer" as const,
    expires_in: 3600,
  };
}

export async function refreshAccessToken(
  refreshToken: string,
  clientId: string,
) {
  const hashedToken = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  const [tokenRow] = await db
    .select()
    .from(refreshTokensTable)
    .where(eq(refreshTokensTable.token, hashedToken))
    .limit(1);

  if (!tokenRow) {
    return {
      error: "invalid_grant",
      error_description: "Invalid refresh token.",
    };
  }

  if (tokenRow.revoked) {
    await db
      .update(refreshTokensTable)
      .set({ revoked: true })
      .where(eq(refreshTokensTable.familyId, tokenRow.familyId));

    return {
      error: "invalid_grant",
      error_description:
        "Token reuse detected. All tokens in this family have been revoked.",
    };
  }

  if (new Date() > tokenRow.expiresAt) {
    return {
      error: "invalid_grant",
      error_description: "Refresh token has expired.",
    };
  }

  if (tokenRow.clientId !== clientId) {
    return { error: "invalid_grant", error_description: "Client ID mismatch." };
  }

  await db
    .update(refreshTokensTable)
    .set({ revoked: true })
    .where(eq(refreshTokensTable.token, hashedToken));

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, tokenRow.userId))
    .limit(1);

  if (!user) {
    return { error: "invalid_grant", error_description: "User not found." };
  }

  const idTokenClaims = buildIdTokenClaims(
    user,
    clientId,
    tokenRow.scope,
    null,
  );

  const accessTokenClaims: AccessTokenClaims = {
    iss: idTokenClaims.iss,
    sub: user.id,
    aud: clientId,
    iat: idTokenClaims.iat,
    exp: idTokenClaims.exp,
    scope: tokenRow.scope,
  };

  const idToken = generateIdToken(idTokenClaims);
  const accessToken = generateAccessToken(accessTokenClaims);
  const newRefreshToken = await issueRefreshToken(
    clientId,
    user.id,
    tokenRow.scope,
    tokenRow.familyId,
  );

  return {
    access_token: accessToken,
    id_token: idToken,
    refresh_token: newRefreshToken,
    token_type: "Bearer" as const,
    expires_in: 3600,
  };
}
