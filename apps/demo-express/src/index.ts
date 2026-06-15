import express from 'express';
import { secureShield } from '@inputshield/express';

const app = express();
const port = process.env.PORT || 3001;

// Basic body parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Apply InputShield globally
app.use(secureShield({
  mode: 'BLOCK', // Will block detected threats
  riskThresholds: { warn: 50, block: 80 }
}));

app.get('/', (req, res) => {
  res.json({ message: 'Hello from Express, protected by InputShield!' });
});

app.post('/api/data', (req, res) => {
  res.json({ message: 'Data received', data: req.body });
});

app.listen(port, () => {
  console.log(`Express Demo running on http://localhost:${port}`);
});
