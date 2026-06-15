# InputShield SDK Explanations

This document tracks changes, design decisions, and how things work across the InputShield SDK.

## Initial Setup & Architecture
- **Monorepo Structure**: Set up using Turborepo and `pnpm`. This allows for highly modular architecture where `core`, `integrations` (express, fastify), and `detectors` are kept in separate, manageable packages, but tested and version-bumped together.
- **Root Files**:
  - `pnpm-workspace.yaml`: Defines `packages/` and `apps/` directories.
  - `turbo.json`: Sets up the caching pipelines for `build`, `lint`, `test`, and `dev`.
  - `package.json`: Contains root-level commands.

## Next Phase
- Scaffolding `@inputshield/config` (TS, ESLint configs)
- Scaffolding `@inputshield/core`

## `@inputshield/types` (Phase 1)
- **Purpose**: A dedicated package for global TypeScript interfaces and enums. 
- **Design Decision**: By placing all core types (`RequestContext`, `ThreatType`, `ShieldConfig`) in a separate package, we prevent circular dependencies between `core`, `detectors`, and `framework-integrations`.
- **Key Concepts**:
  - `RequestContext`: An abstraction over Express/Fastify request objects. It normalizes headers, body, query parameters, IP, etc., so the detectors only have to handle one standard data structure.
  - `SecurityAction`: The possible outcomes (`ALLOW`, `WARN`, `THROTTLE`, `CHALLENGE`, `BLOCK`).
  - `ThreatType`: Enum classifying specific attack vectors.

## `@inputshield/core` (Phase 1/2)
- **Purpose**: The brain of the SDK. It orchestrates the execution of detectors and evaluates the overall risk.
- **Key Components**:
  - `ShieldEngine`: The main class instantiated by the framework adapters. It accepts a `RequestContext`, runs all registered `Detector`s concurrently, and delegates to the `RiskAggregator`.
  - `RiskAggregator`: Evaluates the raw `DetectorResult` array. Currently uses a "max score" approach, mapping the highest score against `ShieldConfig.riskThresholds`.
  - `Detector` Interface: The contract all security detectors must follow.

## `@inputshield/detectors` (Phase 2)
- **Purpose**: A collection of specific threat detectors that implement the `Detector` interface.
- **Design Decision**: Detectors are isolated in their own package so users can potentially import only the ones they need, or community members can contribute new detectors easily.
- **Current Detectors**:
  - `SQLInjectionDetector`: Uses regex patterns to identify common SQLi attack vectors in body, headers, and query strings.
  - `XSSDetector`: Identifies potential Cross-Site Scripting payloads.
  - `PathTraversalDetector`: Checks for directory traversal patterns (e.g., `../`).

## Framework Integrations (Phase 3)
### `@inputshield/express`
- **Purpose**: A drop-in middleware for Express.js applications.
- **Design Decision**: Extracts request context using Express's `req` object (`req.ip`, `req.headers`, etc.) and invokes the `ShieldEngine`. If a block action is triggered, it immediately sends a `403 Forbidden` or `429 Too Many Requests` without calling `next()`.

### `@inputshield/fastify`
- **Purpose**: A Fastify plugin using `fastify-plugin` for seamless integration.
- **Design Decision**: Hooks into `preHandler` lifecycle event. Ensures proper extraction of request properties native to Fastify, and gracefully handles `onClose` to clear rate limit intervals preventing memory leaks.

## Next Phase
- Build simple Demo apps in `apps/demo-express` and `apps/demo-fastify`.
- Setup build/compilation testing across the monorepo.
