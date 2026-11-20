import 'dotenv/config';
import express from 'express';

const app = express();
const PORT = process.env.PORT || 5000;

app.get('/', (req, res) => {
  res.status(200).json({
    name: 'FixMate API',
    version: '1.0.0',
    status: 'running',
  });
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`FixMate server running on port ${PORT}`);
  });
}

export default app;
