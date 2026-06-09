import { Router, type Router as RouterType } from "express";
import { authLimiter } from "../../common/middleware.js";
import {
  authenticateClient,
  exchangeAuthorizationCode,
  refreshAccessToken,
} from "./token.service.js";

const router: RouterType = Router();

router.post("/token", authLimiter, async (req, res) => {
  let clientId: string | undefined = req.body.client_id;
  let clientSecret: string | undefined = req.body.client_secret;

  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString();
    const colonIndex = decoded.indexOf(":");
    if (colonIndex !== -1) {
      clientId = decodeURIComponent(decoded.slice(0, colonIndex));
      clientSecret = decodeURIComponent(decoded.slice(colonIndex + 1));
    }
  }

  if (!clientId || !clientSecret) {
    return res.status(401).json({
      error: "invalid_client",
      error_description: "Client authentication required.",
    });
  }

  const client = await authenticateClient(clientId, clientSecret);
  if (!client) {
    return res.status(401).json({
      error: "invalid_client",
      error_description: "Client authentication failed.",
    });
  }

  const grantType: string | undefined = req.body.grant_type;
  const grantTypes: string[] = JSON.parse(client.grantTypes);

  if (!grantType || !grantTypes.includes(grantType)) {
    return res.status(400).json({
      error: "unauthorized_client",
      error_description: "Client is not authorized for this grant type.",
    });
  }

  if (grantType === "authorization_code") {
    const result = await exchangeAuthorizationCode(
      req.body.code,
      clientId,
      req.body.redirect_uri,
      req.body.code_verifier,
    );

    if ("error" in result) {
      return res.status(400).json(result);
    }

    return res.json(result);
  }

  if (grantType === "refresh_token") {
    const result = await refreshAccessToken(req.body.refresh_token, clientId);

    if ("error" in result) {
      return res.status(400).json(result);
    }

    return res.json(result);
  }

  return res.status(400).json({
    error: "unsupported_grant_type",
    error_description: "Supported: authorization_code, refresh_token.",
  });
});

export { router as tokenRouter };
