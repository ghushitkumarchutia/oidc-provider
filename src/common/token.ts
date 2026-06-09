import JWT from "jsonwebtoken";
import { PRIVATE_KEY, PUBLIC_KEY } from "./cert.js";

export interface IDTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  nonce?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
}

export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  scope: string;
}

export function generateIdToken(claims: IDTokenClaims): string {
  return JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });
}

export function generateAccessToken(claims: AccessTokenClaims): string {
  return JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });
}

export function verifyAccessToken(token: string): AccessTokenClaims {
  return JWT.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] }) as AccessTokenClaims;
}
