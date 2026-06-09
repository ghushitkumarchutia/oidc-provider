import "dotenv/config";
import express from "express";
import cors from "cors";
import path from "node:path";
import { discoveryRouter } from "./modules/discovery/discovery.routes.js";
import { authRouter } from "./modules/auth/auth.routes.js";
import { errorHandler } from "./common/middleware.js";

const app = express();
const PORT = process.env.PORT ?? 8080;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.resolve("public")));
app.use(cors());

app.get("/", (_, res) => res.json({ message: "OIDC Provider" }));
app.get("/health", (_, res) =>
  res.json({ message: "Server is healthy", healthy: true }),
);

app.use(discoveryRouter);
app.use(authRouter);

app.use(errorHandler as express.ErrorRequestHandler);

app.listen(PORT, () => {
  console.log(`OIDC Provider is running on PORT ${PORT}`);
});
