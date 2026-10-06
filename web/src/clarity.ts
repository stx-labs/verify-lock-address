import { ClarityType } from '@stacks/transactions';

export class ShapeError extends Error {
  constructor(read: string) {
    super(`${read} returned a value of an unexpected shape`);
    this.name = 'ShapeError';
  }
}

export type Shape =
  | { readonly kind: 'uint' }
  | { readonly kind: 'buffer' }
  | { readonly kind: 'optional'; readonly inner: Shape }
  | { readonly kind: 'ok'; readonly inner: Shape }
  | { readonly kind: 'tuple'; readonly fields: Readonly<Record<string, Shape>> };

export type Decoded<S> = S extends { kind: 'uint' }
  ? bigint
  : S extends { kind: 'buffer' }
    ? string
    : S extends { kind: 'optional'; inner: infer I }
      ? Decoded<I> | null
      : S extends { kind: 'ok'; inner: infer I }
        ? Decoded<I>
        : S extends { kind: 'tuple'; fields: infer F }
          ? { -readonly [K in keyof F]: Decoded<F[K]> }
          : never;

interface RawClarityValue {
  type?: unknown;
  value?: any;
}

export const UINT = { kind: 'uint' } as const;
export const BUFFER = { kind: 'buffer' } as const;
export const optional = <S extends Shape>(inner: S) => ({ kind: 'optional', inner }) as const;
export const ok = <S extends Shape>(inner: S) => ({ kind: 'ok', inner }) as const;
export const tuple = <F extends Record<string, Shape>>(fields: F) => ({ kind: 'tuple', fields }) as const;

function match(cv: RawClarityValue | null | undefined, shape: Shape, read: string): unknown {
  const bad: () => never = () => {
    throw new ShapeError(read);
  };
  if (!cv || typeof cv !== 'object') bad();
  switch (shape.kind) {
    case 'uint': {
      if (cv.type !== ClarityType.UInt) bad();
      const value = BigInt(cv.value);
      if (value < 0n) bad();
      return value;
    }
    case 'buffer':
      if (cv.type !== ClarityType.Buffer || typeof cv.value !== 'string' || !/^[0-9a-f]*$/i.test(cv.value)) bad();
      return cv.value.toLowerCase();
    case 'optional':
      if (cv.type === ClarityType.OptionalNone) return null;
      if (cv.type !== ClarityType.OptionalSome) bad();
      return match(cv.value, shape.inner, read);
    case 'ok':
      if (cv.type !== ClarityType.ResponseOk) bad();
      return match(cv.value, shape.inner, read);
    case 'tuple': {
      if (cv.type !== ClarityType.Tuple || !cv.value || typeof cv.value !== 'object') bad();
      const names = Object.keys(cv.value).sort();
      const expected = Object.keys(shape.fields).sort();
      if (names.length !== expected.length || names.some((n, i) => n !== expected[i])) bad();
      return Object.fromEntries(expected.map(n => [n, match(cv.value[n], shape.fields[n], read)]));
    }
    default:
      return bad();
  }
}

export function decodeReply<S extends Shape>(cv: RawClarityValue | null | undefined, shape: S, read: string): Decoded<S> {
  return match(cv, shape, read) as Decoded<S>;
}

export const isHeight = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;

export const POX5_REPLIES = {
  'get-protocol-bond': optional(
    tuple({
      'early-unlock-bytes': BUFFER,
      'min-ustx-ratio': UINT,
      'stx-value-ratio': UINT,
      'target-rate': UINT,
    })
  ),
  'construct-lockup-output-script': ok(BUFFER),
};

export type Pox5Read = keyof typeof POX5_REPLIES;

export type Pox5Reply<F extends Pox5Read> = Decoded<(typeof POX5_REPLIES)[F]>;
