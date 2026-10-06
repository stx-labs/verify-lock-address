import { lookup } from 'node:dns/promises';

import { REAL_FETCH } from './offline.mjs';

const TRANSIENT_STATUSES = new Set([408, 425, 429]);
const TRANSIENT_STATUS_TEXT = /\bResponse (408|425|429|5\d\d)\b/;
export const TRANSIENT_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ECONNABORTED',
  'EPIPE',
  'ENETUNREACH',
  'EHOSTUNREACH',
  'ETIMEDOUT',
  'EAI_AGAIN',
  'UND_ERR_SOCKET',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
]);

const OFFLINE_CODES = new Set(['ENOTFOUND', 'EAI_AGAIN']);

export const CONTROL_HOST = 'github.com';

export const isTransientStatus = status => TRANSIENT_STATUSES.has(status) || (status >= 500 && status <= 599);

function errorNodes(e, seen = new Set()) {
  if (!e || typeof e !== 'object' || seen.has(e)) return [];
  seen.add(e);
  const nested = Array.isArray(e.errors) ? e.errors.flatMap(inner => errorNodes(inner, seen)) : [];
  return [e, ...nested, ...errorNodes(e.cause, seen)];
}

const errorCodes = e => errorNodes(e).flatMap(node => (typeof node.code === 'string' ? [node.code] : []));

export const PAGE_TIMEOUT = /did not answer within/;
export const PAGE_CANCELLED = /verification was cancelled/;
const LOOPBACK = /^(127\.|::1$|::ffff:127\.)|\blocalhost\b|\b127\.0\.0\.\d+\b|\[::1\]/;

const isLoopbackRefusal = e =>
  errorNodes(e).some(node => node.code === 'ECONNREFUSED') &&
  errorNodes(e).some(node => LOOPBACK.test(String(node.address ?? '')) || LOOPBACK.test(String(node.message ?? '')));

export const deadlineError = ms => new Error(`the page did not finish verifying within ${ms / 1000} s`);

export function isTransient(e) {
  if (!e) return false;
  if (errorNodes(e).some(node => PAGE_TIMEOUT.test(String(node.message ?? '')) || PAGE_CANCELLED.test(String(node.message ?? '')))) {
    return false;
  }
  if (isLoopbackRefusal(e)) return false;
  if (e.name === 'AbortError' || e.name === 'TimeoutError') return true;
  if (errorCodes(e).some(code => TRANSIENT_CODES.has(code))) return true;
  return TRANSIENT_STATUS_TEXT.test(String(e.message ?? ''));
}

export function throwIfTransientGap(result) {
  for (const e of Object.values(result.readErrors ?? {})) {
    if (isTransient(e)) throw e;
  }
  return result;
}

export async function skipOnTransient(t, body) {
  try {
    return await body();
  } catch (e) {
    if (!isTransient(e)) throw e;
    t.skip(`live API unavailable: ${String(e.message ?? e).slice(0, 160)}`);
    return undefined;
  }
}

export async function reachable(t, url, fetchImpl = REAL_FETCH, { resolveControl = () => lookup(CONTROL_HOST) } = {}) {
  let response;
  try {
    response = await fetchImpl(url, { signal: AbortSignal.timeout(8000) });
  } catch (e) {
    if (isTransient(e)) {
      t.skip(`live API unavailable: ${String(e.message ?? e).slice(0, 160)}`);
      return false;
    }
    if (errorCodes(e).some(code => OFFLINE_CODES.has(code))) {
      const online = await resolveControl().then(
        () => true,
        () => false
      );
      if (!online) {
        t.skip(`offline: neither ${new URL(url).host} nor ${CONTROL_HOST} resolves`);
        return false;
      }
    }
    throw e;
  }
  if (response.ok) return true;
  if (isTransientStatus(response.status)) {
    t.skip(`live API unavailable: HTTP ${response.status}`);
    return false;
  }
  throw new Error(`${url} answered HTTP ${response.status}`);
}
