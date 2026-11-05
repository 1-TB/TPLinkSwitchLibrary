import { describe, expect, it } from 'vitest';
import { assembleFragments, packHeader, packTlvs, PACKET_END, unpackTlvs } from '../src/protocol.js';
import { OpCode } from '../src/types.js';

const MAC = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

function fragPacket(fragmentOffset: number, payload: Buffer): Buffer {
  const header = {
    version: 1,
    opCode: OpCode.RETURN,
    switchMac: MAC,
    hostMac: MAC,
    sequenceId: 42,
    errorCode: 0,
    checkLength: 0,
    fragmentOffset,
    flag: 0,
    tokenId: 0,
    checksum: 0,
  };
  return Buffer.concat([packHeader(header), payload, PACKET_END]);
}

describe('assembleFragments', () => {
  it('concatenates fragments in descending fragmentOffset order', () => {
    const first = packTlvs([{ type: 768, value: Buffer.from('FIRST', 'latin1') }]);
    const last = packTlvs([{ type: 768, value: Buffer.from('LAST', 'latin1') }]);
    const out = assembleFragments([fragPacket(0, last), fragPacket(1, first)]);
    const tlvs = unpackTlvs(out);
    expect(tlvs.map((t) => t.value.toString('latin1'))).toEqual(['FIRST', 'LAST']);
  });

  it('drops the duplicate copy of each fragment', () => {
    const first = packTlvs([{ type: 768, value: Buffer.from('A', 'latin1') }]);
    const last = packTlvs([{ type: 768, value: Buffer.from('B', 'latin1') }]);
    // The switch sends every fragment twice, ~100ms apart.
    const out = assembleFragments([
      fragPacket(1, first),
      fragPacket(1, first),
      fragPacket(0, last),
      fragPacket(0, last),
    ]);
    const tlvs = unpackTlvs(out);
    expect(tlvs.map((t) => t.value.toString('latin1'))).toEqual(['A', 'B']);
  });

  it('returns a single-packet reply unchanged', () => {
    const payload = packTlvs([{ type: 2, value: Buffer.from('hello', 'latin1') }]);
    const out = assembleFragments([fragPacket(0, payload)]);
    expect(out).toEqual(payload);
  });

  it('reassembles a real captured export shape (TLV 768 chunks)', () => {
    // Mirror of the live capture: two TLV 768 chunks, fragOff 1 then 0.
    const tlv = (v: Buffer) => packTlvs([{ type: 768, value: v }]);
    const out = assembleFragments([fragPacket(0, tlv(Buffer.alloc(8, 0x45))), fragPacket(1, tlv(Buffer.alloc(8, 0x23)))]);
    expect(out.toString('hex')).toBe('03000008' + '2323232323232323' + '03000008' + '4545454545454545');
  });
});
