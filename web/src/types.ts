import type { PoxInfo } from '@stacks/bitcoin-staking';
import type { StacksNetwork } from '@stacks/network';

import type { Tail } from './script-view.ts';

export type NetworkName = 'private-1' | 'mainnet';

export interface Network {
  label: string;
  api: string;
  hrp: string;
  boot: string;
  stacks: StacksNetwork;
  badge: string;
  prefixes: string[];
}

export interface Alternate {
  label: string | undefined;
  address: string;
}

export interface Comparison {
  supplied: string;
  match: boolean;
}

export interface VerifyInput {
  network: NetworkName;
  bondIndex: number;
  stxAddress: string;
  unlockBytes: Uint8Array;
  altUnlockBytes?: Uint8Array | null;
  altLabel?: string;
  expected?: string | null;
  heightOverride?: number;
}

export interface VerifyResult {
  net: Network;
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
  alternate: Alternate | null;
  comparison: Comparison | null;
  notes: string[];
  bondIndex: number;
  stxAddress: string;
}
