# InputShield SDK

**InputShield** is a production-grade, highly modular Node.js security SDK designed to sit as a middleware between incoming API requests and your application business logic. 

It analyzes every request in real time, inspecting headers, body, query parameters, IP address, and request patterns to assign a risk score and dynamically block, throttle, or allow the request.

## Features
- **Plug-and-play Integrations**: Works natively with Express and Fastify out of the box.
- **Advanced Threat Detectors**: Real-time protection against SQLi, XSS, and Path Traversal attacks.
- **Smart Rate Limiting**: Built-in memory (and soon Redis) rate-limiting stores to prevent API abuse.
- **Risk Scoring Engine**: Configurable thresholds to seamlessly toggle between `OBSERVE`, `WARN`, and `BLOCK` modes.

## Getting Started

InputShield is designed to be added to an existing backend with minimal configuration.

### Installation
```bash
# For Express
npm install @inputshield/express

# For Fastify
npm install @inputshield/fastify
```

### Usage (Express Example)
```typescript
import express from 'express';
import { secureShield } from '@inputshield/express';

const app = express();

// Apply the InputShield middleware globally
app.use(secureShield({
  mode: 'BLOCK', // Will automatically block requests that exceed the risk threshold
  riskThresholds: { warn: 50, block: 80 },
  detectors: {
    sqli: true,
    xss: true,
    pathTraversal: true
  }
}));

app.get('/', (req, res) => {
  res.send('Your API is now protected!');
});

app.listen(3000);
```

## Architecture
Built as a Turborepo monorepo, the core engine (`@inputshield/core`) and threat detectors (`@inputshield/detectors`) are completely framework-agnostic. They are bound to Express and Fastify via lightweight adapter packages.
