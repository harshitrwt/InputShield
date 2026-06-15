import Fastify from 'fastify';
import { secureShield } from '@inputshield/fastify';

const fastify = Fastify({ logger: true });

// Apply InputShield globally
fastify.register(secureShield, {
  mode: 'BLOCK', // Will block detected threats
  riskThresholds: { warn: 50, block: 80 }
});

fastify.get('/', async (request, reply) => {
  return { message: 'Hello from Fastify, protected by InputShield!' };
});

fastify.post('/api/data', async (request, reply) => {
  return { message: 'Data received', data: request.body };
});

const start = async () => {
  try {
    await fastify.listen({ port: 3002 });
    console.log(`Fastify Demo running on http://localhost:3002`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};
start();
