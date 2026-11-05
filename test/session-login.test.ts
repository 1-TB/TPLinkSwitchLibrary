import { describe, expect, it } from 'vitest';
import { SwitchClient } from '../src/client.js';
import { assembleFragments, assemblePacket, packHeader, PACKET_END, serializeString, splitPacket, unpackTlvs } from '../src/protocol.js';
import { RSA_OK } from '../src/session.js';
import { OpCode, PacketHeader, SecurityPreference, TlvEntry, TlvType } from '../src/types.js';

type Request = { opCode: OpCode; tlvs: TlvEntry[]; useSession: boolean };
type Reply = { errorCode?: number; tlvs?: TlvEntry[] } | 'timeout';

/** Stands in for UdpTransport: hands each request to a handler, returns its reply. */
class FakeTransport {
  host = { mac: Buffer.from([1, 2, 3, 4, 5, 6]), ip: '127.0.0.1', name: 'fake', broadcast: '127.255.255.255' };
  sent: Request[] = [];
  sessionKey: string | null = null;
  closed = false;
  private pending: { header: PacketHeader; reply: Reply } | null = null;

  constructor(private handler: (req: Request) => Reply) {}

  setSessionCipher(key: string | null): void {
    this.sessionKey = key;
  }

  async send(packet: Buffer, useSession = false): Promise<void> {
    const { header, payload } = splitPacket(packet);
    const req = { opCode: header.opCode, tlvs: unpackTlvs(payload), useSession: useSession && this.sessionKey !== null };
    this.sent.push(req);
    this.pending = { header, reply: this.handler(req) };
  }

  async receiveAssembled(timeoutMs: number): Promise<Buffer> {
    const p = this.pending!;
    this.pending = null;
    if (p.reply === 'timeout') throw new Error(`receive timed out after ${timeoutMs}ms`);
    return assemblePacket(
      { ...p.header, opCode: OpCode.RETURN, errorCode: p.reply.errorCode ?? 0, tokenId: 7 },
      p.reply.tlvs ?? [],
    );
  }

  close(): void {
    this.closed = true;
  }
}

const BAD_LOGIN = 3;
const NOT_PERMITTED = 5;

/**
 * Simulates 2023+ firmware: ACKs any TLV 528 key, adopts the 1024-bit one only
 * when acceptBig is set, and while a session is active ignores every legacy
 * request except TLV 528 (the lock-out the PR describes).
 */
function rsaSwitch(opts: { acceptBig: boolean; password?: string; config?: Buffer[] }) {
  const password = serializeString(opts.password ?? 'admin', true);
  const state = { session: false };
  const handler = (req: Request): Reply => {
    const rsa = req.tlvs.find((t) => t.type === TlvType.RSA_KEY);
    if (rsa) {
      if (rsa.value.length === 0) state.session = false;
      else state.session = rsa.value.length === 130 ? opts.acceptBig : true;
      return { errorCode: RSA_OK };
    }
    if (req.useSession !== state.session) return 'timeout';
    if (req.opCode === OpCode.LOGIN) {
      const pw = req.tlvs.find((t) => t.type === TlvType.PASSWORD);
      if (!pw || !pw.value.equals(password)) return { errorCode: BAD_LOGIN };
      if (req.tlvs.some((t) => t.type === TlvType.SYSTEM_CONFIG_GET)) {
        if (!state.session) return { errorCode: NOT_PERMITTED };
        return { tlvs: (opts.config ?? []).map((value) => ({ type: TlvType.SYSTEM_CONFIG_GET, value })) };
      }
    }
    return {};
  };
  return { handler, state };
}

/** Simulates old firmware that never answers TLV 528. */
function legacySwitch(password = 'admin') {
  const pw = serializeString(password, true);
  return (req: Request): Reply => {
    if (req.useSession) return 'timeout';
    if (req.tlvs.some((t) => t.type === TlvType.RSA_KEY)) return 'timeout';
    if (req.opCode === OpCode.LOGIN) {
      const p = req.tlvs.find((t) => t.type === TlvType.PASSWORD);
      if (!p || !p.value.equals(pw)) return { errorCode: BAD_LOGIN };
      if (req.tlvs.some((t) => t.type === TlvType.SYSTEM_CONFIG_GET)) {
        return { tlvs: [{ type: TlvType.SYSTEM_CONFIG_GET, value: Buffer.from('OLD') }] };
      }
    }
    return {};
  };
}

function client(fake: FakeTransport, security?: SecurityPreference, password = 'admin'): SwitchClient {
  const c = new SwitchClient({ switchMac: 'aa:bb:cc:dd:ee:ff', password, timeout: 50, security });
  (c as unknown as { transport: FakeTransport }).transport = fake;
  // An 'error' event without a listener would throw from emit(); tests assert on the rejection instead.
  c.on('error', () => undefined);
  return c;
}

const sentRsaKeys = (fake: FakeTransport) =>
  fake.sent.flatMap((r) => r.tlvs.filter((t) => t.type === TlvType.RSA_KEY).map((t) => t.value.length));

describe('login security preference', () => {
  it("defaults to 'legacy' and never sends a session key", async () => {
    const sw = rsaSwitch({ acceptBig: false });
    const fake = new FakeTransport(sw.handler);
    const c = client(fake);
    await c.login();
    expect(c.securityMode).toBe('legacy');
    expect(sentRsaKeys(fake)).toEqual([]);
    expect(sw.state.session).toBe(false);
  });

  it("'auto' falls back to the 64-bit key when the 1024-bit one is ACKed but not adopted", async () => {
    const sw = rsaSwitch({ acceptBig: false });
    const fake = new FakeTransport(sw.handler);
    const c = client(fake, 'auto');
    await c.login();
    expect(c.securityMode).toBe('rsa-small');
    expect(sentRsaKeys(fake)).toEqual([130, 10]);
  });

  it("'auto' uses the legacy transport on firmware without TLV 528", async () => {
    const fake = new FakeTransport(legacySwitch());
    const c = client(fake, 'auto');
    await c.login();
    expect(c.securityMode).toBe('legacy');
  });

  it("'rsa' throws when the switch has no RSA support", async () => {
    const c = client(new FakeTransport(legacySwitch()), 'rsa');
    await expect(c.login()).rejects.toThrow(/did not accept an RSA session key/);
  });

  it('rejects a wrong password over an RSA session and clears the session it opened', async () => {
    const sw = rsaSwitch({ acceptBig: true, password: 'right' });
    const fake = new FakeTransport(sw.handler);
    const c = client(fake, 'auto', 'wrong');
    await expect(c.login()).rejects.toThrow(/rejected login/);
    // The 1024-bit key was adopted, so no 64-bit retry, and an empty key was sent to unlock.
    expect(sentRsaKeys(fake)).toEqual([130, 0]);
    expect(sw.state.session).toBe(false);
    expect(c.securityMode).toBe('legacy');
    expect(fake.sessionKey).toBeNull();
  });

  it('rejects a wrong password on the legacy transport', async () => {
    const c = client(new FakeTransport(legacySwitch('right')), 'legacy', 'wrong');
    await expect(c.login()).rejects.toThrow(/error code 3/);
  });
});

describe('backupConfig', () => {
  it('opens a temporary session from a legacy login and leaves the switch unlocked', async () => {
    const sw = rsaSwitch({ acceptBig: true, config: [Buffer.from('AB'), Buffer.from('CD')] });
    const fake = new FakeTransport(sw.handler);
    const c = client(fake);
    await c.login();
    const cfg = await c.backupConfig();
    expect(cfg.toString()).toBe('ABCD');
    expect(c.securityMode).toBe('legacy');
    expect(sw.state.session).toBe(false);
    // Still usable over legacy afterwards.
    await expect(c.getInfo()).resolves.toBeDefined();
  });

  it('keeps an existing RSA session open', async () => {
    const sw = rsaSwitch({ acceptBig: true, config: [Buffer.from('X')] });
    const fake = new FakeTransport(sw.handler);
    const c = client(fake, 'rsa');
    await c.login();
    expect((await c.backupConfig()).toString()).toBe('X');
    expect(c.securityMode).toBe('rsa-big');
    expect(sw.state.session).toBe(true);
  });

  it('works over the legacy transport on old firmware, probing RSA only once', async () => {
    const fake = new FakeTransport(legacySwitch());
    const c = client(fake);
    await c.login();
    expect((await c.backupConfig()).toString()).toBe('OLD');
    expect((await c.backupConfig()).toString()).toBe('OLD');
    expect(sentRsaKeys(fake)).toEqual([130, 10]);
  });

  it('clears the temporary session even when the export fails', async () => {
    const sw = rsaSwitch({ acceptBig: true });
    const fake = new FakeTransport(sw.handler);
    const c = client(fake);
    await c.login();
    await expect(c.backupConfig()).rejects.toThrow(/no data TLV/);
    expect(sw.state.session).toBe(false);
    expect(c.securityMode).toBe('legacy');
  });
});

describe('logout and close', () => {
  it('logout resets local state even when the switch does not answer', async () => {
    const sw = rsaSwitch({ acceptBig: true });
    let silent = false;
    const fake = new FakeTransport((req) => (silent ? 'timeout' : sw.handler(req)));
    const c = client(fake, 'rsa');
    await c.login();
    silent = true;
    await expect(c.logout()).rejects.toThrow(/timed out/);
    expect(c.securityMode).toBe('legacy');
    expect(fake.sessionKey).toBeNull();
  });

  it('close clears an active session before closing the sockets', async () => {
    const sw = rsaSwitch({ acceptBig: true });
    const fake = new FakeTransport(sw.handler);
    const c = client(fake, 'rsa');
    await c.login();
    await c.close();
    expect(sw.state.session).toBe(false);
    expect(fake.closed).toBe(true);
  });

  it('close does not send a session clear after a legacy login', async () => {
    const fake = new FakeTransport(legacySwitch());
    const c = client(fake);
    await c.login();
    await c.close();
    expect(sentRsaKeys(fake)).toEqual([]);
    expect(fake.closed).toBe(true);
  });
});

describe('assembleFragments end marker', () => {
  it('keeps every payload byte of a fragment that has no end marker', () => {
    const header = (fragmentOffset: number): PacketHeader => ({
      version: 1,
      opCode: OpCode.RETURN,
      switchMac: Buffer.alloc(6),
      hostMac: Buffer.alloc(6),
      sequenceId: 1,
      errorCode: 0,
      checkLength: 0,
      fragmentOffset,
      flag: 0,
      tokenId: 0,
      checksum: 0,
    });
    const first = Buffer.concat([packHeader(header(1)), Buffer.from('ABCDEFGH')]);
    const last = Buffer.concat([packHeader(header(0)), Buffer.from('IJ'), PACKET_END]);
    expect(assembleFragments([last, first]).toString()).toBe('ABCDEFGHIJ');
  });
});
