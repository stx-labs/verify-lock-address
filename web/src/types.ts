import type { PoxInfo } from '@stacks/bitcoin-staking';
import type { StacksNetwork } from '@stacks/network';

import type { InvalidTargetReason } from './address.ts';
import type { Tail } from './script-view.ts';
import type { Check } from './verdict.ts';

export type NetworkName = 'private-1' | 'mainnet';

export type Mode = 'single' | 'multi';

export interface Network {
  label: string;
  api: string;
  hrp: string;
  boot: string;
  stacks: StacksNetwork;
  badge: string;
  prefixes: string[];
}

export interface ErrorLike {
  message: string;
}

export type Settled<T> = { ok: true; value: T } | { ok: false; error: unknown };

export interface Comparison {
  match: boolean;
  reason: 'match' | 'mismatch' | 'wrong-network' | InvalidTargetReason;
  display: string | null;
}

export interface VerifyInput {
  network: NetworkName;
  mode?: Mode;
  bondIndex: number;
  stxAddress: string;
  unlockBytes: Uint8Array;
  ambiguousKeysConfirmed?: boolean;
  expected?: string | null;
  heightOverride?: number;
}

export interface VerifyFacts {
  net: Network;
  mode: Mode;
  tail: Tail;
  unlockBytes: Uint8Array;
  earlyUnlockBytes: string;
  poxInfo: PoxInfo;
  derivedHeight: number;
  unlockHeight: number;
  heightOverridden: boolean;
  lockScript: Uint8Array;
  sdkScript: string;
  contractScript: string;
  agree: boolean;
  address: string;
  comparison: Comparison | null;
  notes: string[];
  bondIndex: number;
  stxAddress: string;
}

export interface VerifyResult extends VerifyFacts {
  checks: Check[];
}
