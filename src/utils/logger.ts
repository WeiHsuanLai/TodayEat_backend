// src/utils/logger.ts

function getCallerLocation(): string {
  const err = new Error();
  const stackLine = (err.stack || '').split('\n')[2] || '';
  const match = stackLine.match(/(?:\()?(.*):(\d+):(\d+)(?:\))?/);
  return match ? `${match[1]}:${match[2]}` : 'unknown';
}

function log(...args: unknown[]) {
  const time = new Date().toISOString();
  const location = getCallerLocation();
  console.log(`[${time}] [LOG @ ${location}]`, ...args);
}

function logWarn(...args: unknown[]) {
  const time = new Date().toISOString();
  const location = getCallerLocation();
  logWarn(`[${time}] [WARN @ ${location}]`, ...args);
}

function logError(...args: unknown[]) {
  const time = new Date().toISOString();
  const location = getCallerLocation();
  logError(`[${time}] [ERROR @ ${location}]`, ...args);
}

// 👉 綁到 global
(globalThis as typeof globalThis & {
  log: typeof log;
  logWarn: typeof logWarn;
  logError: typeof logError;
}).log = log;

globalThis.log = log;
globalThis.logWarn = logWarn;
globalThis.logError = logError;
