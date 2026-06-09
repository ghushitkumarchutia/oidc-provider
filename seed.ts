import bcrypt from "bcrypt";
import { db } from "./src/db/index.js";
import { usersTable, clientsTable } from "./src/db/schema.js";

const BCRYPT_ROUNDS = 12;

async function seed() {
  const clientSecretHash = await bcrypt.hash("demo-secret", BCRYPT_ROUNDS);

  await db
    .insert(clientsTable)
    .values({
      clientId: "demo-app",
      clientSecret: clientSecretHash,
      clientName: "Demo Application",
      redirectUris: JSON.stringify(["http://localhost:3000/callback"]),
      grantTypes: JSON.stringify(["authorization_code", "refresh_token"]),
    })
    .onConflictDoNothing();

  console.log("Seeded client: demo-app / demo-secret");

  const passwordHash = await bcrypt.hash("password123", BCRYPT_ROUNDS);

  await db
    .insert(usersTable)
    .values({
      firstName: "John",
      lastName: "Doe",
      email: "john@example.com",
      password: passwordHash,
    })
    .onConflictDoNothing();

  console.log("Seeded user: john@example.com / password123");

  process.exit(0);
}

seed();
