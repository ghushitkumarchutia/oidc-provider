import { Router, type Router as RouterType } from "express";
import { authLimiter } from "../../common/middleware.js";
import {
  validateAuthorizeParams,
  authenticateUser,
  getClientName,
  createConsentSession,
  getConsentSession,
  generateAuthorizationCode,
  registerUser,
} from "./auth.service.js";

const router: RouterType = Router();

function errorPage(message: string) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Authorization Error</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#09090b;color:#fafafa;display:flex;align-items:center;justify-content:center;min-height:100dvh}
.card{max-width:360px;padding:2rem;background:#18181b;border:1px solid #27272a;border-radius:12px;text-align:center}
h1{font-size:1.25rem;font-weight:600;margin-bottom:0.75rem}
p{color:#a1a1aa;font-size:0.875rem;line-height:1.5}
</style>
</head>
<body><div class="card"><h1>Authorization Error</h1><p>${message}</p></div></body>
</html>`;
}

router.get("/authorize", async (req, res) => {
  const params = {
    response_type: req.query.response_type as string | undefined,
    client_id: req.query.client_id as string | undefined,
    redirect_uri: req.query.redirect_uri as string | undefined,
    scope: req.query.scope as string | undefined,
    code_challenge: req.query.code_challenge as string | undefined,
    code_challenge_method: req.query.code_challenge_method as string | undefined,
  };

  const state = req.query.state as string | undefined;
  const nonce = req.query.nonce as string | undefined;

  const result = await validateAuthorizeParams(params);

  if (!result.valid && !result.safe) {
    return res.status(400).contentType("html").send(errorPage(result.error!));
  }

  if (!result.valid && result.safe) {
    const url = new URL(params.redirect_uri!);
    url.searchParams.set("error", result.errorCode!);
    url.searchParams.set("error_description", result.errorDesc!);
    if (state) url.searchParams.set("state", state);
    return res.redirect(url.toString());
  }

  const loginParams = new URLSearchParams();
  loginParams.set("response_type", "code");
  loginParams.set("client_id", params.client_id!);
  loginParams.set("redirect_uri", params.redirect_uri!);
  loginParams.set("scope", params.scope!);
  loginParams.set("client_name", result.clientName!);
  if (state) loginParams.set("state", state);
  if (nonce) loginParams.set("nonce", nonce);
  if (params.code_challenge) loginParams.set("code_challenge", params.code_challenge);
  if (params.code_challenge_method) loginParams.set("code_challenge_method", params.code_challenge_method);

  return res.redirect(`/login.html?${loginParams}`);
});

router.post("/authorize/callback", authLimiter, async (req, res) => {
  const {
    email,
    password,
    client_id,
    redirect_uri,
    scope,
    state,
    nonce,
    code_challenge,
    code_challenge_method,
  } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  const user = await authenticateUser(email, password);
  if (!user) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  const clientName = await getClientName(client_id);

  const session = createConsentSession({
    userId: user.id,
    clientId: client_id,
    clientName: clientName || client_id,
    redirectUri: redirect_uri,
    scope,
    state: state || null,
    nonce: nonce || null,
    codeChallenge: code_challenge || null,
    codeChallengeMethod: code_challenge_method || null,
  });

  const consentParams = new URLSearchParams();
  consentParams.set("session", session);
  consentParams.set("client_name", clientName || client_id);
  consentParams.set("scope", scope);

  return res.json({ redirect: `/consent.html?${consentParams}` });
});

router.post("/authorize/consent", async (req, res) => {
  const { session: sessionId, approved } = req.body;

  if (!sessionId) {
    return res.status(400).json({ message: "Missing session." });
  }

  const session = getConsentSession(sessionId);
  if (!session) {
    return res.status(400).json({ message: "Invalid or expired consent session." });
  }

  const redirectUrl = new URL(session.redirectUri);

  if (!approved) {
    redirectUrl.searchParams.set("error", "access_denied");
    if (session.state) redirectUrl.searchParams.set("state", session.state);
    return res.json({ redirect: redirectUrl.toString() });
  }

  const code = await generateAuthorizationCode(
    session.userId,
    session.clientId,
    session.redirectUri,
    session.scope,
    session.nonce,
    session.codeChallenge,
    session.codeChallengeMethod,
  );

  redirectUrl.searchParams.set("code", code);
  if (session.state) redirectUrl.searchParams.set("state", session.state);

  return res.json({ redirect: redirectUrl.toString() });
});

router.post("/signup", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (!firstName || !email || !password) {
    return res.status(400).json({ message: "First name, email, and password are required." });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: "Password must be at least 8 characters." });
  }

  const created = await registerUser(firstName, lastName || null, email, password);
  if (!created) {
    return res.status(409).json({ message: "An account with this email already exists." });
  }

  return res.status(201).json({ message: "Account created successfully." });
});

export { router as authRouter };
