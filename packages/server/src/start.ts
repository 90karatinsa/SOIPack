import path from 'path';
import process from 'process';

import dotenv from 'dotenv';

import { createServer } from './index';

dotenv.config();

const token = process.env.SOIPACK_API_TOKEN;

if (!token) {
  // eslint-disable-next-line no-console
  console.error('SOIPACK_API_TOKEN ortam değişkeni tanımlanmalıdır.');
  process.exit(1);
}

const storageDir = process.env.SOIPACK_STORAGE_DIR
  ? path.resolve(process.env.SOIPACK_STORAGE_DIR)
  : path.resolve('.soipack/server');
const portSource = process.env.PORT ?? '3000';
const port = Number.parseInt(portSource, 10);

if (Number.isNaN(port) || port <= 0) {
  // eslint-disable-next-line no-console
  console.error('Geçerli bir PORT değeri belirtilmelidir.');
  process.exit(1);
}

const app = createServer({ token, storageDir });

app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`SOIPack API ${port} portunda çalışıyor.`);
});

