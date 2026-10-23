const INPUT_CHARSET =
  '0123456789()[],\'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';
const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATORS = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];

function polymod(c: bigint, val: number): bigint {
  const c0 = c >> 35n;
  let out = ((c & 0x7ffffffffn) << 5n) ^ BigInt(val);
  for (let i = 0; i < 5; i += 1) if ((c0 >> BigInt(i)) & 1n) out ^= GENERATORS[i];
  return out;
}

export function descriptorChecksum(body: string): string {
  let c = 1n;
  let cls = 0;
  let clsCount = 0;
  for (const ch of body) {
    const pos = INPUT_CHARSET.indexOf(ch);
    if (pos === -1) throw new Error('The descriptor contains a character descriptors cannot hold.');
    c = polymod(c, pos & 31);
    cls = cls * 3 + (pos >> 5);
    clsCount += 1;
    if (clsCount === 3) {
      c = polymod(c, cls);
      cls = 0;
      clsCount = 0;
    }
  }
  if (clsCount > 0) c = polymod(c, cls);
  for (let i = 0; i < 8; i += 1) c = polymod(c, 0);
  c ^= 1n;
  let out = '';
  for (let j = 0; j < 8; j += 1) out += CHECKSUM_CHARSET[Number((c >> BigInt(5 * (7 - j))) & 31n)];
  return out;
}
