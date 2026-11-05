import dgram from 'node:dgram';
import os from 'node:os';
import { decode, encode } from './cipher.js';
import { assembleFragments, HEADER_LENGTH, PACKET_END, packHeader, splitPacket } from './protocol.js';
import { sessionRC4 } from './session.js';
import { PacketHeader } from './types.js';

export const SWITCH_PORT = 29808;
export const CLIENT_PORT = 29809;
export const BROADCAST_ADDR = '255.255.255.255';

export interface HostInterface {
  name: string;
  ip: string;
  mac: Buffer;
}

export function resolveInterface(name?: string): HostInterface {
  const all = os.networkInterfaces();
  const candidates: HostInterface[] = [];
  for (const [ifname, addrs] of Object.entries(all)) {
    if (!addrs) continue;
    if (name && ifname !== name) continue;
    for (const a of addrs) {
      if (a.family !== 'IPv4' || a.internal) continue;
      if (!a.mac || a.mac === '00:00:00:00:00:00') continue;
      candidates.push({
        name: ifname,
        ip: a.address,
        mac: Buffer.from(a.mac.split(':').map((p) => parseInt(p, 16))),
      });
    }
  }
  if (!candidates.length) throw new Error(`no suitable IPv4 interface${name ? ` named ${name}` : ''}`);
  return candidates[0];
}

export class UdpTransport {
  readonly host: HostInterface;
  private send_: dgram.Socket;
  private recv_: dgram.Socket;
  private queue: Buffer[] = [];
  private waiters: Array<(b: Buffer) => void> = [];
  private ready: Promise<void>;
  private closed = false;
  private sessionKey: string | null = null;

  constructor(interfaceName?: string) {
    this.host = resolveInterface(interfaceName);
    this.send_ = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this.recv_ = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    this.recv_.on('message', (msg) => {
      const plain = this.decrypt(msg);
      if (!plain || plain.length < HEADER_LENGTH) return;
      // ignore own outgoing broadcast echo: client sends opcodes 0/1/3
      const op = plain.readInt8(1);
      if (op !== 2 && op !== 4) return;
      const w = this.waiters.shift();
      if (w) w(plain);
      else this.queue.push(plain);
    });

    this.ready = new Promise<void>((resolve, reject) => {
      let pending = 2;
      const done = () => { if (--pending === 0) resolve(); };
      this.send_.once('error', reject);
      this.recv_.once('error', reject);
      this.send_.bind({ address: this.host.ip, port: CLIENT_PORT, exclusive: false }, () => {
        try { this.send_.setBroadcast(true); } catch { /* ignore */ }
        done();
      });
      this.recv_.bind({ address: '0.0.0.0', port: CLIENT_PORT, exclusive: false }, () => {
        try { this.recv_.setBroadcast(true); } catch { /* ignore */ }
        done();
      });
    });
  }

  async start(): Promise<void> {
    await this.ready;
  }

  /** Switch between legacy static RC4 and the RSA session cipher (null = legacy). */
  setSessionCipher(key: string | null): void {
    this.sessionKey = key;
  }

  /** Try the legacy cipher first, then the session cipher when one is active. */
  private decrypt(raw: Buffer): Buffer | null {
    const d1 = decode(raw);
    if (d1.length >= 2 && d1[0] === 1 && d1[1] < 5) return d1;
    if (this.sessionKey) {
      const d2 = sessionRC4(raw, this.sessionKey);
      if (d2.length >= 2 && d2[0] === 1 && d2[1] < 5) return d2;
    }
    return null;
  }

  async send(packet: Buffer, useSession = false): Promise<void> {
    await this.ready;
    const enc = useSession && this.sessionKey ? sessionRC4(packet, this.sessionKey) : encode(packet);
    await new Promise<void>((resolve, reject) => {
      this.send_.send(enc, 0, enc.length, SWITCH_PORT, BROADCAST_ADDR, (err) => {
        if (err) reject(err); else resolve();
      });
    });
  }

  async receive(timeoutMs: number): Promise<Buffer> {
    await this.ready;
    if (this.queue.length) return this.queue.shift()!;
    return new Promise<Buffer>((resolve, reject) => {
      const t = setTimeout(() => {
        const idx = this.waiters.indexOf(w);
        if (idx >= 0) this.waiters.splice(idx, 1);
        reject(new Error(`receive timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      const w = (b: Buffer) => { clearTimeout(t); resolve(b); };
      this.waiters.push(w);
    });
  }

  async receiveAll(timeoutMs: number): Promise<Buffer[]> {
    await this.ready;
    const deadline = Date.now() + timeoutMs;
    const out: Buffer[] = [...this.queue];
    this.queue = [];
    while (true) {
      const remain = deadline - Date.now();
      if (remain <= 0) break;
      try {
        const p = await this.receive(remain);
        out.push(p);
      } catch {
        break;
      }
    }
    return out;
  }

  // Assembles fragmented responses keyed by sequenceId.
  // Fragments arrive with fragmentOffset counting down to 0 on the last one,
  // and the switch sends each fragment twice. Collection ends once offset 0
  // and every offset above it (up to the highest seen) are in, and no new
  // fragment has arrived for settleMs. If the deadline passes first, this
  // throws instead of returning a partial reply.
  // Returns a well-formed packet: last fragment's header + all payloads.
  async receiveAssembled(timeoutMs: number, sequenceId?: number, settleMs = 0): Promise<Buffer> {
    const deadline = Date.now() + timeoutMs;
    const fragments = new Map<number, Buffer>();
    let expectedSeq: number | null = sequenceId ?? null;
    let finalHeader: PacketHeader | null = null;
    let maxOffset = 0;
    let lastArrival = 0;
    const missing = (): number[] => {
      const out: number[] = [];
      for (let o = maxOffset; o >= 0; o--) if (!fragments.has(o)) out.push(o);
      return out;
    };
    const incomplete = (): Error =>
      new Error(
        `receive timed out after ${timeoutMs}ms with an incomplete fragmented reply ` +
          `(missing fragment offsets ${missing().join(', ')})`,
      );
    while (true) {
      const complete = finalHeader !== null && missing().length === 0;
      const waitUntil = complete ? Math.min(lastArrival + settleMs, deadline) : deadline;
      const remain = waitUntil - Date.now();
      if (remain <= 0) {
        if (complete) break;
        if (fragments.size) throw incomplete();
        throw new Error(`receive timed out after ${timeoutMs}ms`);
      }
      let pkt: Buffer;
      try {
        pkt = await this.receive(remain);
      } catch (err) {
        if (complete) break;
        if (fragments.size) throw incomplete();
        throw err;
      }
      let header: PacketHeader;
      try {
        ({ header } = splitPacket(pkt));
      } catch {
        continue;
      }
      if (expectedSeq === null) expectedSeq = header.sequenceId;
      else if (header.sequenceId !== expectedSeq) continue;
      const offset = header.fragmentOffset;
      if (offset < 0 || fragments.has(offset)) continue; // duplicate copy
      fragments.set(offset, pkt);
      if (offset > maxOffset) maxOffset = offset;
      if (offset === 0) finalHeader = header;
      lastArrival = Date.now();
    }
    const payload = assembleFragments([...fragments.values()]);
    return Buffer.concat([packHeader(finalHeader!), payload, PACKET_END]);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try { this.send_.close(); } catch { /* ignore */ }
    try { this.recv_.close(); } catch { /* ignore */ }
  }
}
