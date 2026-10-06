import type { Mode, VerifyFacts, VerifyResult } from './types.ts';

export const CHECK_ORDER = ['script', 'expected', 'tail'] as const;

export type CheckId = (typeof CHECK_ORDER)[number];

export type CheckStatus = 'pass' | 'fail' | 'unknown';

export interface Check {
  id: CheckId;
  status: CheckStatus;
  reason: string;
}

export type VerdictState = 'match' | 'fail' | 'unverified';

export interface Verdict {
  state: VerdictState;
  check: Check | null;
}

export const REQUIRED_CHECKS: Record<Mode, CheckId[]> = {
  single: ['script', 'tail', 'expected'],
  multi: ['script', 'tail', 'expected'],
};

const check = (id: CheckId, status: CheckStatus, reason: string): Check => ({ id, status, reason });

function scriptCheck(r: VerifyFacts): Check {
  if (r.agree === true) return check('script', 'pass', 'agree');
  if (r.agree === false) return check('script', 'fail', 'disagree');
  return check('script', 'unknown', 'unread');
}

function expectedCheck(r: VerifyFacts): Check {
  const c = r.comparison;
  if (!c) return check('expected', 'unknown', 'missing');
  if (c.match === true) return check('expected', 'pass', 'match');
  const reason = ['mixed-case', 'unreadable', 'wrong-network'].includes(c.reason) ? c.reason : 'mismatch';
  return check('expected', 'fail', reason);
}

function tailCheck(r: VerifyFacts): Check {
  const kind = r.tail?.kind;
  if (kind !== 'single' && kind !== 'multisig') return check('tail', 'fail', 'unknown-kind');
  if (r.tail.verify !== false) return check('tail', 'fail', 'verify');
  return check('tail', 'pass', 'ok');
}

export const COMPARED_REASONS = ['match', 'mismatch', 'wrong-network'];

export function revealsComputed(r: Pick<VerifyFacts, 'comparison'> | null | undefined): boolean {
  const c = r?.comparison;
  return Boolean(c) && typeof c === 'object' && c !== null && COMPARED_REASONS.includes(c.reason) && typeof c.display === 'string' && c.display !== '';
}

export function checkMode(r: { mode?: unknown }): Mode | null {
  return r.mode === 'single' || r.mode === 'multi' ? r.mode : null;
}

export function deriveChecks(r: VerifyFacts): Check[] {
  return [scriptCheck(r), expectedCheck(r), tailCheck(r)];
}

const rank = (id: CheckId) => {
  const at = CHECK_ORDER.indexOf(id);
  return at === -1 ? CHECK_ORDER.length : at;
};

export function computeVerdict(result: VerifyResult | null | undefined): Verdict {
  const mode = checkMode(result ?? {});
  const checks = Array.isArray(result?.checks) ? result.checks.filter(c => c && typeof c === 'object') : [];
  const ordered = [...checks].sort((a, b) => rank(a.id) - rank(b.id));

  const failed = ordered.find(c => c.status === 'fail');
  if (failed) return { state: 'fail', check: failed };

  if (!mode) return { state: 'unverified', check: null };
  for (const id of REQUIRED_CHECKS[mode]) {
    const matching = checks.filter(c => c.id === id);
    const gap = matching.find(c => c.status !== 'pass');
    if (!matching.length) return { state: 'unverified', check: { id, status: 'unknown', reason: 'absent' } };
    if (gap) return { state: 'unverified', check: gap };
  }
  const stray = ordered.find(c => c.status !== 'pass');
  if (stray) return { state: 'unverified', check: stray };
  return { state: 'match', check: null };
}
