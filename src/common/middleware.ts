import type { Request, Response, NextFunction } from "express";
import rateLimit from "express-rate-limit";

export const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many requests, please try again later." },
});

export function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  console.error(err.message);
  res.status(500).json({ message: "Internal server error." });
}
