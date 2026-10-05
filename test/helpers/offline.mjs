import assert from 'node:assert/strict';
import { after } from 'node:test';

export const REAL_FETCH = globalThis.fetch;

const attempts = [];

export const guardFetch = async url => {
  attempts.push(String(url));
  throw new Error(`a non-live test reached for the network: ${url}`);
};

globalThis.fetch = guardFetch;

after(() => assert.deepEqual(attempts, [], 'a non-live test reached for the network'));

export async function live(body) {
  globalThis.fetch = REAL_FETCH;
  try {
    return await body();
  } finally {
    globalThis.fetch = guardFetch;
  }
}

export const takeAttempts = () => attempts.splice(0);
