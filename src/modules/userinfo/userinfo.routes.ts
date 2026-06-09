import { Router, type Router as RouterType } from "express";
import { eq } from "drizzle-orm";
import { verifyAccessToken } from "../../common/token.js";
import { db } from "../../db/index.js";
import { usersTable } from "../../db/schema.js";

const router: RouterType = Router();

router.get("/userinfo", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "invalid_request", error_description: "Missing Bearer token." });
  }

  const token = authHeader.slice(7);

  let claims;
  try {
    claims = verifyAccessToken(token);
  } catch {
    return res.status(401).json({ error: "invalid_token", error_description: "Invalid or expired access token." });
  }

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, claims.sub))
    .limit(1);

  if (!user) {
    return res.status(401).json({ error: "invalid_token", error_description: "User not found." });
  }

  const scopes = claims.scope.split(" ");
  const response: Record<string, unknown> = { sub: user.id };

  if (scopes.includes("email")) {
    response.email = user.email;
    response.email_verified = user.emailVerified;
  }

  if (scopes.includes("profile")) {
    response.name = [user.firstName, user.lastName].filter(Boolean).join(" ");
    response.given_name = user.firstName;
    response.family_name = user.lastName;
    response.picture = user.profileImageURL;
  }

  return res.json(response);
});

export { router as userinfoRouter };
