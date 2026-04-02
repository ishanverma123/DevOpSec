import cors from "cors";
import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import { rateLimit } from "express-rate-limit";

import { env } from "./config/env";
import { errorHandler, notFoundHandler } from "./middleware/error";
import apiRouter from "./routes";

const app = express();

// Accept comma-separated origins so local + deployed frontend can coexist.
const allowedOrigins = env.CORS_ORIGIN.split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    // Allow same-server calls and tools that don't send Origin.
    if (!origin) {
      callback(null, true);
      return;
    }

    if (allowedOrigins.includes("*") || allowedOrigins.includes(origin)) {
      callback(null, true);
      return;
    }

    callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 204
};

app.use(helmet());
app.use(cors(corsOptions));
// Reply to preflight requests before hitting route handlers.
app.options("*", cors(corsOptions));
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    skip: (req) => req.method === "OPTIONS",
    standardHeaders: true,
    legacyHeaders: false
  })
);
app.use(morgan("combined"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

app.use("/api/v1", apiRouter);
app.use(notFoundHandler);
app.use(errorHandler);

export default app;
