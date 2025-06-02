// src/utils/logger.ts

function log(...args: unknown[]) {
  const err = new Error();
  const stackLine = (err.stack || '').split('\n')[2] || '';
  const match = stackLine.match(/(?:\()?(.*):(\d+):(\d+)(?:\))?/);
  const location = match ? `${match[1]}:${match[2]}` : 'unknown';
  const time = new Date().toISOString();
  console.log(`[${time}] [LOG @ ${location}]`, ...args);
}

// 👉 把 log 綁到 global
(globalThis as typeof globalThis & { log: typeof log }).log = log;
