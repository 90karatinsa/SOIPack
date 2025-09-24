import { config } from 'dotenv';

import { DatabaseManager } from '../database';

config();

async function main(): Promise<void> {
  const manager = DatabaseManager.fromEnv();
  try {
    await manager.initialize();
  } finally {
    await manager.close();
  }
}

main().then(
  () => {
    // eslint-disable-next-line no-console
    console.log('Migrations applied successfully.');
  },
  (error) => {
    const message = error instanceof Error ? error.message : String(error);
    // eslint-disable-next-line no-console
    console.error(`Migration failed: ${message}`);
    process.exitCode = 1;
  },
);
