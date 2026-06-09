import {
  uuid,
  pgTable,
  varchar,
  text,
  boolean,
  timestamp,
} from "drizzle-orm/pg-core";

export const usersTable = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),

  firstName: varchar("first_name", { length: 25 }),
  lastName: varchar("last_name", { length: 25 }),

  profileImageURL: text("profile_image_url"),

  email: varchar("email", { length: 322 }).notNull().unique(),
  emailVerified: boolean("email_verified").default(false).notNull(),

  password: varchar("password", { length: 60 }).notNull(),

  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").$onUpdate(() => new Date()),
});

export const clientsTable = pgTable("clients", {
  id: uuid("id").primaryKey().defaultRandom(),

  clientId: varchar("client_id", { length: 64 }).notNull().unique(),
  clientSecret: varchar("client_secret", { length: 60 }).notNull(),
  clientName: varchar("client_name", { length: 100 }).notNull(),

  redirectUris: text("redirect_uris").notNull(),
  grantTypes: text("grant_types").notNull(),

  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const authorizationCodesTable = pgTable("authorization_codes", {
  id: uuid("id").primaryKey().defaultRandom(),

  code: varchar("code", { length: 64 }).notNull().unique(),

  clientId: varchar("client_id", { length: 64 }).notNull(),
  userId: uuid("user_id").notNull(),
  redirectUri: text("redirect_uri").notNull(),
  scope: varchar("scope", { length: 200 }).notNull(),

  nonce: varchar("nonce", { length: 128 }),
  codeChallenge: varchar("code_challenge", { length: 128 }),
  codeChallengeMethod: varchar("code_challenge_method", { length: 6 }),

  expiresAt: timestamp("expires_at").notNull(),
  used: boolean("used").default(false).notNull(),

  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const refreshTokensTable = pgTable("refresh_tokens", {
  id: uuid("id").primaryKey().defaultRandom(),

  token: varchar("token", { length: 64 }).notNull().unique(),
  familyId: varchar("family_id", { length: 64 }).notNull(),

  clientId: varchar("client_id", { length: 64 }).notNull(),
  userId: uuid("user_id").notNull(),
  scope: varchar("scope", { length: 200 }).notNull(),

  expiresAt: timestamp("expires_at").notNull(),
  revoked: boolean("revoked").default(false).notNull(),

  createdAt: timestamp("created_at").defaultNow().notNull(),
});
