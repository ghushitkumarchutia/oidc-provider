import { Router, type Router as RouterType } from "express";
import jose from "node-jose";
import { PUBLIC_KEY } from "../../common/cert.js";

const router: RouterType = Router();

router.get("/.well-known/openid-configuration", (_, res) => {
  const ISSUER = `http://localhost:${process.env.PORT ?? 8080}`;

  return res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    userinfo_endpoint: `${ISSUER}/userinfo`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    scopes_supported: ["openid", "profile", "email"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: [
      "client_secret_post",
      "client_secret_basic",
    ],
    claims_supported: [
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "email",
      "email_verified",
      "name",
      "given_name",
      "family_name",
      "picture",
    ],
    code_challenge_methods_supported: ["S256"],
  });
});

router.get("/.well-known/jwks.json", async (_, res) => {
  const key = await jose.JWK.asKey(PUBLIC_KEY, "pem");
  return res.json({ keys: [key.toJSON()] });
});

export { router as discoveryRouter };
