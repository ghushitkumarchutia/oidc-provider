import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { eq } from "drizzle-orm";
import { db } from "../../db/index.js";
import {
  usersTable,
  clientsTable,
  authorizationCodesTable,
} from "../../db/schema.js";

const BCRYPT_ROUNDS = 12;

interface ConsentSession {
  userId: string;
  clientId: string;
  clientName: string;
  redirectUri: string;
  scope: string;
  state: string | null;
  nonce: string | null;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  expiresAt: number;
}

const consentSessions = new Map<string, ConsentSession>();

export async function validateAuthorizeParams(params: {
  response_type?: string | undefined;
  client_id?: string | undefined;
  redirect_uri?: string | undefined;
  scope?: string | undefined;
  code_challenge?: string | undefined;
  code_challenge_method?: string | undefined;
}) {
  if (!params.client_id) {
    return { valid: false, error: "client_id is required.", safe: false };
  }

  const [client] = await db
    .select()
    .from(clientsTable)
    .where(eq(clientsTable.clientId, params.client_id))
    .limit(1);

  if (!client) {
    return { valid: false, error: "Unknown client_id.", safe: false };
  }

  const uris: string[] = JSON.parse(client.redirectUris);
  if (!params.redirect_uri || !uris.includes(params.redirect_uri)) {
    return { valid: false, error: "Invalid redirect_uri.", safe: false };
  }

  if (params.response_type !== "code") {
    return {
      valid: false,
      errorCode: "invalid_request",
      errorDesc: "response_type must be 'code'.",
      safe: true,
    };
  }

  if (!params.scope || !params.scope.split(" ").includes("openid")) {
    return {
      valid: false,
      errorCode: "invalid_scope",
      errorDesc: "scope must include 'openid'.",
      safe: true,
    };
  }

  if (params.code_challenge && params.code_challenge_method !== "S256") {
    return {
      valid: false,
      errorCode: "invalid_request",
      errorDesc: "code_challenge_method must be 'S256'.",
      safe: true,
    };
  }

  return { valid: true, clientName: client.clientName };
}

export async function authenticateUser(email: string, password: string) {
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (!user) return null;

  const match = await bcrypt.compare(password, user.password);
  if (!match) return null;

  return user;
}

export async function getClientName(clientId: string) {
  const [client] = await db
    .select({ clientName: clientsTable.clientName })
    .from(clientsTable)
    .where(eq(clientsTable.clientId, clientId))
    .limit(1);

  return client?.clientName ?? null;
}

export function createConsentSession(
  data: Omit<ConsentSession, "expiresAt">,
): string {
  const sessionId = crypto.randomBytes(32).toString("hex");
  consentSessions.set(sessionId, {
    ...data,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });
  return sessionId;
}

export function getConsentSession(sessionId: string): ConsentSession | null {
  const session = consentSessions.get(sessionId);
  if (!session) return null;

  consentSessions.delete(sessionId);

  if (Date.now() > session.expiresAt) return null;

  return session;
}

export async function generateAuthorizationCode(
  userId: string,
  clientId: string,
  redirectUri: string,
  scope: string,
  nonce: string | null,
  codeChallenge: string | null,
  codeChallengeMethod: string | null,
) {
  const rawCode = crypto.randomBytes(32).toString("hex");
  const hashedCode = crypto
    .createHash("sha256")
    .update(rawCode)
    .digest("hex");

  await db.insert(authorizationCodesTable).values({
    code: hashedCode,
    clientId,
    userId,
    redirectUri,
    scope,
    nonce,
    codeChallenge,
    codeChallengeMethod,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
  });

  return rawCode;
}

export async function registerUser(
  firstName: string,
  lastName: string | null,
  email: string,
  password: string,
) {
  const [existing] = await db
    .select({ id: usersTable.id })
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (existing) return false;

  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  await db.insert(usersTable).values({
    firstName,
    lastName,
    email,
    password: hash,
  });

  return true;
}
