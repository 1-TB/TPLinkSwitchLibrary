import { EventEmitter } from 'node:events';
import {
  assemblePacket,
  buildSwitchInfo,
  parseBandwidthEntry,
  parseBool,
  parseCableTestResult,
  parseMirrorConfig,
  parseMtuVlanConfig,
  parsePoeExtend,
  parsePoePort,
  parsePoeSystem,
  parsePortConfig,
  parsePortStats,
  parsePortVlanEntry,
  parsePvid,
  parseQosPriority,
  parseStormControl,
  parseVlan,
  serializeBandwidthEntry,
  serializeBool,
  serializeCableTestRequest,
  serializeIp,
  serializeMac,
  serializeMirrorConfig,
  serializeMtuVlanConfig,
  serializePoeExtend,
  serializePoePort,
  serializePoeSystemLimit,
  serializePortConfig,
  serializePortVlanEntry,
  serializePvid,
  serializeQosPriority,
  serializeStormControl,
  serializeString,
  serializeVlan,
  splitPacket,
  unpackTlvs,
} from './protocol.js';
import { UdpTransport } from './transport.js';
import { RSA_BIG_MODULUS, RSA_OK, RSA_SMALL_MODULUS, newSessionKey, rsaEncryptSessionKey } from './session.js';
import {
  BandwidthConfig,
  BandwidthEntry,
  CableTestResult,
  IpConfig,
  MirrorConfig,
  MtuVlanConfig,
  OpCode,
  PacketHeader,
  PoeExtendEntry,
  PoePortConfig,
  PoePriority,
  PoeSystem,
  PortConfig,
  PortStatistics,
  PortVlanConfig,
  PortVlanEntry,
  PvidConfig,
  QosConfig,
  QosPriority,
  SecurityMode,
  StormControlEntry,
  SwitchClientOptions,
  SwitchConfig,
  SwitchInfo,
  TlvEntry,
  TlvType,
  VlanConfig,
} from './types.js';

/**
 * How long to keep listening after a fragmented reply looks complete. The
 * switch sends every fragment twice ~100ms apart, so this window lets the
 * second copy fill in a fragment whose first copy was lost.
 */
const FRAGMENT_SETTLE_MS = 250;

/** The switch adopted the session key but rejected the credentials. */
class LoginRejectedError extends Error {}

export class SwitchClient extends EventEmitter {
  private opts: Required<SwitchClientOptions>;
  private transport?: UdpTransport;
  private switchMac: Buffer;
  private sequenceId = Math.floor(Math.random() * 1000);
  private tokenId = 0;
  private sessionKey: string | null = null;
  /** Set once both RSA handshakes failed, so later calls skip the timeouts. */
  private rsaUnsupported = false;
  /** Transport security negotiated by login(). */
  securityMode: SecurityMode = 'legacy';

  constructor(opts: SwitchClientOptions) {
    super();
    this.opts = {
      switchMac: opts.switchMac,
      interface: opts.interface ?? '',
      username: opts.username ?? 'admin',
      password: opts.password ?? 'admin',
      timeout: opts.timeout ?? 2000,
      security: opts.security ?? 'legacy',
    };
    this.switchMac = serializeMac(opts.switchMac);
  }

  private async transport_(): Promise<UdpTransport> {
    if (!this.transport) {
      this.transport = new UdpTransport(this.opts.interface || undefined);
      await this.transport.start();
    }
    return this.transport;
  }

  private nextSeq(): number {
    this.sequenceId = (this.sequenceId + 1) % 1000;
    return this.sequenceId;
  }

  private buildHeader(opCode: OpCode, hostMac: Buffer): PacketHeader {
    return {
      version: 1,
      opCode,
      switchMac: this.switchMac,
      hostMac,
      sequenceId: this.nextSeq(),
      errorCode: 0,
      checkLength: 0,
      fragmentOffset: 0,
      flag: 0,
      tokenId: this.tokenId,
      checksum: 0,
    };
  }

  /** Send a request and return the raw reply. Does not throw on error codes. */
  private async queryRaw(
    opCode: OpCode,
    tlvs: TlvEntry[],
    useSession: boolean,
    settleMs = 0,
  ): Promise<{ header: PacketHeader; tlvs: TlvEntry[] }> {
    const t = await this.transport_();
    const header = this.buildHeader(opCode, t.host.mac);
    const packet = assemblePacket(header, tlvs);
    await t.send(packet, useSession);
    const reply = await t.receiveAssembled(this.opts.timeout, header.sequenceId, settleMs);
    const { header: rh, payload } = splitPacket(reply);
    this.tokenId = rh.tokenId;
    return { header: rh, tlvs: unpackTlvs(payload) };
  }

  private useSession(): boolean {
    return this.securityMode !== 'legacy' && this.sessionKey !== null;
  }

  private async query(
    opCode: OpCode,
    tlvs: TlvEntry[],
    useSession = this.useSession(),
    settleMs = 0,
  ): Promise<{ header: PacketHeader; tlvs: TlvEntry[] }> {
    let res: { header: PacketHeader; tlvs: TlvEntry[] };
    try {
      res = await this.queryRaw(opCode, tlvs, useSession, settleMs);
    } catch (err) {
      // Surface timeouts via a dedicated event (Phase 4 spec).
      if (err instanceof Error && /timed out/i.test(err.message)) {
        this.emit('timeout', err);
      }
      throw err;
    }
    if (res.header.errorCode !== 0) {
      const err = new Error(`switch returned error code ${res.header.errorCode}`);
      this.emit('error', err);
      throw err;
    }
    return res;
  }

  private async refreshToken(): Promise<void> {
    await this.query(OpCode.GET, [{ type: TlvType.GET_TOKEN_ID, value: Buffer.alloc(0) }]);
  }

  private loginTlvs(): TlvEntry[] {
    return [
      { type: TlvType.USERNAME, value: serializeString(this.opts.username, true) },
      { type: TlvType.PASSWORD, value: serializeString(this.opts.password, true) },
    ];
  }

  /**
   * Negotiate an RSA session key (TLV 528) and verify the switch adopted it.
   * The ACK alone doesn't prove adoption — e.g. the TL-SG1024DE v7 ACKs the
   * 1024-bit key but only activates the session for the 64-bit key — so the
   * session is confirmed with an encrypted token GET before use.
   */
  private async tryRSASession(modulus: Buffer, mode: SecurityMode): Promise<boolean> {
    const t = await this.transport_();
    const key = newSessionKey();
    let adopted = false;
    let established = false;
    this.sessionKey = key;
    t.setSessionCipher(key);
    try {
      const rsa = rsaEncryptSessionKey(key, modulus);
      // The handshake itself always goes out static-encrypted.
      const ack = await this.queryRaw(OpCode.LOGIN, [{ type: TlvType.RSA_KEY, value: rsa }], false);
      if (ack.header.errorCode !== RSA_OK) return false;
      // A reply to a session-encrypted request proves the switch adopted the key;
      // a switch that only ACKed it ignores the request and this times out.
      const token = await this.queryRaw(
        OpCode.GET,
        [{ type: TlvType.GET_TOKEN_ID, value: Buffer.alloc(0) }],
        true,
      );
      adopted = true;
      if (token.header.errorCode !== 0) return false;
      const auth = await this.queryRaw(OpCode.LOGIN, this.loginTlvs(), true);
      if (auth.header.errorCode !== 0) {
        throw new LoginRejectedError(`switch rejected login (error code ${auth.header.errorCode})`);
      }
      this.securityMode = mode;
      established = true;
      return true;
    } catch (err) {
      // Bad credentials are a real failure, not a reason to try another mode.
      if (err instanceof LoginRejectedError) throw err;
      return false;
    } finally {
      if (!established) {
        // Don't leave the switch session-locked after a half-finished handshake.
        if (adopted) await this.sendSessionClear().catch(() => undefined);
        this.clearLocalSession();
      }
    }
  }

  /** Try an RSA session with the 1024-bit key, then the 64-bit one. */
  private async startSession(): Promise<boolean> {
    if (this.rsaUnsupported) return false;
    if (await this.tryRSASession(RSA_BIG_MODULUS, 'rsa-big')) return true;
    if (await this.tryRSASession(RSA_SMALL_MODULUS, 'rsa-small')) return true;
    this.rsaUnsupported = true;
    return false;
  }

  private async legacyLogin(): Promise<void> {
    await this.query(OpCode.GET, [{ type: TlvType.GET_TOKEN_ID, value: Buffer.alloc(0) }], false);
    await this.query(OpCode.LOGIN, this.loginTlvs(), false);
  }

  private clearLocalSession(): void {
    this.sessionKey = null;
    this.securityMode = 'legacy';
    this.transport?.setSessionCipher(null);
  }

  /** Empty TLV 528, always static-encrypted. Throws unless the switch ACKs it. */
  private async sendSessionClear(): Promise<void> {
    const res = await this.queryRaw(OpCode.LOGIN, [{ type: TlvType.RSA_KEY, value: Buffer.alloc(0) }], false);
    if (res.header.errorCode !== RSA_OK) {
      throw new Error(`switch did not acknowledge session clear (error code ${res.header.errorCode})`);
    }
  }

  async login(): Promise<void> {
    // The transport is chosen by opts.security (default 'legacy'). RSA is opt-in
    // because an RSA session makes the switch ignore legacy-only tools until it
    // is cleared. backupConfig() opens a temporary session when it needs one.
    await this.transport_();
    this.clearLocalSession();
    try {
      if (this.opts.security !== 'legacy') {
        if (await this.startSession()) return;
        if (this.opts.security === 'rsa') {
          throw new Error('switch did not accept an RSA session key (tried 1024-bit and 64-bit)');
        }
      }
      await this.legacyLogin();
    } catch (err) {
      if (err instanceof LoginRejectedError) this.emit('error', err);
      throw err;
    }
  }

  private async authedSet(tlvs: TlvEntry[]): Promise<{ header: PacketHeader; tlvs: TlvEntry[] }> {
    await this.refreshToken();
    return this.query(OpCode.LOGIN, [...this.loginTlvs(), ...tlvs]);
  }

  // ---------- system info / network config ----------

  async getInfo(): Promise<SwitchInfo> {
    // Firmware quirk: GET must carry exactly one query TLV. Any info query
    // returns every info field, so asking for hostname yields the full set.
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.HOSTNAME, value: Buffer.alloc(0) }]);
    return buildSwitchInfo(tlvs);
  }

  async setHostname(hostname: string): Promise<void> {
    await this.authedSet([{ type: TlvType.HOSTNAME, value: serializeString(hostname, true) }]);
  }

  /**
   * Configure the management interface. Pass `{ dhcp: true }` to request DHCP;
   * the static fields are zeroed in that case to mirror the official utility.
   */
  async setIpConfig(cfg: IpConfig): Promise<void> {
    const mgmtVlan = cfg.managementVlan ?? 1;
    const tlvs: TlvEntry[] = [
      { type: TlvType.DHCP, value: Buffer.from([cfg.dhcp ? 1 : 0]) },
    ];
    if (cfg.dhcp) {
      tlvs.push({ type: TlvType.IP_ADDR, value: Buffer.alloc(4) });
      tlvs.push({ type: TlvType.IP_MASK, value: Buffer.alloc(4) });
      tlvs.push({ type: TlvType.GATEWAY, value: Buffer.alloc(4) });
    } else {
      if (!cfg.ipAddress || !cfg.subnetMask || !cfg.gateway) {
        throw new Error('static IP requires ipAddress, subnetMask, and gateway');
      }
      tlvs.push({ type: TlvType.IP_ADDR, value: serializeIp(cfg.ipAddress) });
      tlvs.push({ type: TlvType.IP_MASK, value: serializeIp(cfg.subnetMask) });
      tlvs.push({ type: TlvType.GATEWAY, value: serializeIp(cfg.gateway) });
    }
    const mv = Buffer.alloc(2);
    mv.writeUInt16BE(mgmtVlan, 0);
    tlvs.push({ type: TlvType.MANAGEMENT_VLAN, value: mv });
    await this.authedSet(tlvs);
  }

  /** Convenience wrapper: enable/disable DHCP without touching other fields. */
  async setDhcp(enabled: boolean, managementVlan = 1): Promise<void> {
    if (enabled) {
      await this.setIpConfig({ dhcp: true, managementVlan });
      return;
    }
    const info = await this.getInfo();
    await this.setIpConfig({
      dhcp: false,
      ipAddress: info.ipAddress,
      subnetMask: info.subnetMask,
      gateway: info.gateway,
      managementVlan,
    });
  }

  async getLed(): Promise<boolean> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.LED_STATUS, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.LED_STATUS);
    return t ? parseBool(t.value) : false;
  }

  async setLed(enabled: boolean): Promise<void> {
    await this.authedSet([{ type: TlvType.LED_STATUS, value: serializeBool(enabled) }]);
  }

  /**
   * Change the admin username/password. Requires the constructor `username`/
   * `password` to match the switch's current credentials — they're sent as
   * TLV 512/513 to authenticate the change. The new credentials go out as
   * 514/515 exactly as the official utility encodes them.
   */
  async setCredentials(newUsername: string, newPassword: string): Promise<void> {
    await this.refreshToken();
    await this.query(OpCode.LOGIN, [
      { type: TlvType.USERNAME, value: serializeString(this.opts.username, true) },
      { type: TlvType.PASSWORD_OLD, value: serializeString(this.opts.password, true) },
      { type: TlvType.PASSWORD, value: serializeString(newUsername, true) },
      { type: TlvType.PASSWORD_NEW, value: serializeString(newPassword, true) },
    ]);
    // Keep the client usable with the new credentials for subsequent calls.
    this.opts.username = newUsername;
    this.opts.password = newPassword;
  }

  async factoryReset(): Promise<void> {
    await this.authedSet([{ type: TlvType.SYSTEM_RESET, value: Buffer.from([1]) }]);
  }

  // ---------- ports ----------

  async getPorts(): Promise<PortConfig[]> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.PORTS, value: Buffer.alloc(0) }]);
    return tlvs.filter((t) => t.type === TlvType.PORTS).map((t) => parsePortConfig(t.value));
  }

  async setPorts(ports: PortConfig[]): Promise<void> {
    await this.authedSet(ports.map((p) => ({ type: TlvType.PORTS, value: serializePortConfig(p) })));
  }

  async getPortStatistics(): Promise<PortStatistics[]> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.PORT_STATISTICS, value: Buffer.alloc(0) }]);
    return tlvs.filter((t) => t.type === TlvType.PORT_STATISTICS).map((t) => parsePortStats(t.value));
  }

  // ---------- 802.1Q VLANs ----------

  async getVlanEnabled(): Promise<boolean> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.VLAN_ENABLED, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.VLAN_ENABLED);
    return t ? parseBool(t.value) : false;
  }

  async setVlanEnabled(enabled: boolean): Promise<void> {
    await this.authedSet([{ type: TlvType.VLAN_ENABLED, value: serializeBool(enabled) }]);
  }

  async getVlans(): Promise<VlanConfig[]> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.VLAN, value: Buffer.alloc(0) }]);
    return tlvs.filter((t) => t.type === TlvType.VLAN && t.value.length >= 10).map((t) => parseVlan(t.value));
  }

  async setVlan(vlan: VlanConfig): Promise<void> {
    // firmware bug: set exactly one VLAN per request
    await this.authedSet([{ type: TlvType.VLAN, value: serializeVlan(vlan) }]);
  }

  async deleteVlan(vlanId: number): Promise<void> {
    await this.setVlan({ vlanId, name: '', memberPorts: [], taggedPorts: [], untaggedPorts: [] });
  }

  async getPvids(): Promise<PvidConfig[]> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.PVID, value: Buffer.alloc(0) }]);
    return tlvs.filter((t) => t.type === TlvType.PVID && t.value.length === 3).map((t) => parsePvid(t.value));
  }

  async setPvid(port: number, pvid: number): Promise<void> {
    await this.setPvids([{ port, pvid }]);
  }

  async setPvids(pvids: PvidConfig[]): Promise<void> {
    await this.authedSet(pvids.map((p) => ({ type: TlvType.PVID, value: serializePvid(p) })));
  }

  /**
   * Read the 802.1Q management-VLAN flag and current value.
   * Returns `null` when the management-VLAN feature is disabled.
   */
  async getManagementVlan(): Promise<{ enabled: boolean; vlanId: number | null }> {
    const { tlvs } = await this.query(OpCode.GET, [
      { type: TlvType.VLAN_8021Q_MANAGEMENT_ENABLED, value: Buffer.alloc(0) },
    ]);
    const enabledT = tlvs.find((x) => x.type === TlvType.VLAN_8021Q_MANAGEMENT_ENABLED);
    const vlanT = tlvs.find((x) => x.type === TlvType.VLAN_8021Q_MANAGEMENT_VLAN);
    const enabled = enabledT ? parseBool(enabledT.value) : false;
    const vlanId = vlanT && vlanT.value.length >= 2 ? vlanT.value.readUInt16BE(0) : null;
    return { enabled, vlanId: vlanId || null };
  }

  async setManagementVlanEnabled(enabled: boolean): Promise<void> {
    await this.authedSet([{ type: TlvType.VLAN_8021Q_MANAGEMENT_ENABLED, value: serializeBool(enabled) }]);
  }

  async setManagementVlan(vlanId: number): Promise<void> {
    const v = Buffer.alloc(2);
    v.writeUInt16BE(vlanId, 0);
    await this.authedSet([{ type: TlvType.VLAN_8021Q_MANAGEMENT_VLAN, value: v }]);
  }

  // ---------- MTU-VLAN mode ----------

  async getMtuVlan(): Promise<MtuVlanConfig> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.MTU_VLAN, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.MTU_VLAN);
    return t ? parseMtuVlanConfig(t.value) : { enabled: false, uplinkPort: 1 };
  }

  async setMtuVlan(cfg: MtuVlanConfig): Promise<void> {
    await this.authedSet([{ type: TlvType.MTU_VLAN, value: serializeMtuVlanConfig(cfg) }]);
  }

  // ---------- port-based VLAN mode ----------

  async getPortVlanConfig(): Promise<PortVlanConfig> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.PORT_VLAN_ENABLED, value: Buffer.alloc(0) }]);
    const enabled = parseBool(tlvs.find((x) => x.type === TlvType.PORT_VLAN_ENABLED)?.value ?? Buffer.alloc(0));
    const entries: PortVlanEntry[] = tlvs
      .filter((x) => x.type === TlvType.PORT_VLAN_ENTRY && x.value.length === 5)
      .map((x) => parsePortVlanEntry(x.value));
    const managementStatus = parseBool(tlvs.find((x) => x.type === TlvType.PORT_VLAN_MANAGEMENT_ENABLED)?.value ?? Buffer.alloc(0));
    const mgmtMaskT = tlvs.find((x) => x.type === TlvType.PORT_VLAN_MANAGEMENT_PORTS);
    const managementPorts = mgmtMaskT && mgmtMaskT.value.length >= 4
      ? Array.from({ length: 32 }, (_, i) => i + 1).filter((p) => (mgmtMaskT.value.readUInt32BE(0) >>> (p - 1)) & 1)
      : [];
    return { enabled, entries, managementStatus, managementPorts };
  }

  async setPortVlanEnabled(enabled: boolean): Promise<void> {
    await this.authedSet([{ type: TlvType.PORT_VLAN_ENABLED, value: serializeBool(enabled) }]);
  }

  async setPortVlanEntry(entry: PortVlanEntry): Promise<void> {
    await this.authedSet([{ type: TlvType.PORT_VLAN_ENTRY, value: serializePortVlanEntry(entry) }]);
  }

  async deletePortVlanEntry(vlanId: number): Promise<void> {
    await this.setPortVlanEntry({ vlanId, memberPorts: [] });
  }

  // ---------- IGMP snooping ----------

  async getIgmpSnooping(): Promise<boolean> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.IGMP_SNOOPING, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.IGMP_SNOOPING);
    return t ? parseBool(t.value) : false;
  }

  async setIgmpSnooping(enabled: boolean): Promise<void> {
    await this.authedSet([{ type: TlvType.IGMP_SNOOPING, value: serializeBool(enabled) }]);
  }

  async getIgmpReportSuppress(): Promise<boolean> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.IGMP_SUPPRESS, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.IGMP_SUPPRESS);
    return t ? parseBool(t.value) : false;
  }

  async setIgmpReportSuppress(enabled: boolean): Promise<void> {
    await this.authedSet([{ type: TlvType.IGMP_SUPPRESS, value: serializeBool(enabled) }]);
  }

  // ---------- QoS ----------

  async getQos(): Promise<QosConfig> {
    // The switch returns both the mode flag and every port-priority entry when
    // you ask for either one; we ask for mode and collect everything.
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.QOS_MODE, value: Buffer.alloc(0) }]);
    const mode = parseBool(tlvs.find((x) => x.type === TlvType.QOS_MODE)?.value ?? Buffer.alloc(0));
    const priorities: QosPriority[] = tlvs
      .filter((x) => x.type === TlvType.QOS_PRIORITY && x.value.length === 2)
      .map((x) => parseQosPriority(x.value));
    return { mode, priorities };
  }

  async setQosMode(enabled: boolean): Promise<void> {
    await this.authedSet([{ type: TlvType.QOS_MODE, value: serializeBool(enabled) }]);
  }

  async setQosPriorities(priorities: QosPriority[]): Promise<void> {
    await this.authedSet(priorities.map((p) => ({ type: TlvType.QOS_PRIORITY, value: serializeQosPriority(p) })));
  }

  // ---------- Bandwidth / storm control ----------

  async getBandwidthControl(): Promise<BandwidthConfig> {
    const { tlvs: ing } = await this.query(OpCode.GET, [{ type: TlvType.BANDWIDTH_INGRESS, value: Buffer.alloc(0) }]);
    const { tlvs: egr } = await this.query(OpCode.GET, [{ type: TlvType.BANDWIDTH_EGRESS, value: Buffer.alloc(0) }]);
    return {
      ingress: ing.filter((t) => t.type === TlvType.BANDWIDTH_INGRESS && t.value.length === 6).map((t) => parseBandwidthEntry(t.value)),
      egress: egr.filter((t) => t.type === TlvType.BANDWIDTH_EGRESS && t.value.length === 6).map((t) => parseBandwidthEntry(t.value)),
    };
  }

  async setBandwidthIngress(entries: BandwidthEntry[]): Promise<void> {
    await this.authedSet(entries.map((e) => ({ type: TlvType.BANDWIDTH_INGRESS, value: serializeBandwidthEntry(e) })));
  }

  async setBandwidthEgress(entries: BandwidthEntry[]): Promise<void> {
    await this.authedSet(entries.map((e) => ({ type: TlvType.BANDWIDTH_EGRESS, value: serializeBandwidthEntry(e) })));
  }

  async getStormControl(): Promise<StormControlEntry[]> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.STORM_CONTROL, value: Buffer.alloc(0) }]);
    return tlvs.filter((t) => t.type === TlvType.STORM_CONTROL && t.value.length === 9).map((t) => parseStormControl(t.value));
  }

  async setStormControl(entries: StormControlEntry[]): Promise<void> {
    await this.authedSet(entries.map((e) => ({ type: TlvType.STORM_CONTROL, value: serializeStormControl(e) })));
  }

  // ---------- Port mirror ----------

  async getMirror(): Promise<MirrorConfig> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.PORT_MIRROR, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.PORT_MIRROR && x.value.length === 10);
    return t
      ? parseMirrorConfig(t.value)
      : { enabled: false, mirrorPort: 0, ingressPorts: [], egressPorts: [] };
  }

  async setMirror(cfg: MirrorConfig): Promise<void> {
    await this.authedSet([{ type: TlvType.PORT_MIRROR, value: serializeMirrorConfig(cfg) }]);
  }

  // ---------- Loop prevention ----------

  async getLoopPrevention(): Promise<boolean> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.LOOP_PREVENTION, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.LOOP_PREVENTION);
    return t ? parseBool(t.value) : false;
  }

  async setLoopPrevention(enabled: boolean): Promise<void> {
    await this.authedSet([{ type: TlvType.LOOP_PREVENTION, value: serializeBool(enabled) }]);
  }

  // ---------- Cable test ----------

  /**
   * Run a TDR cable test on one port. The request is a SET; the switch replies
   * with a 6-byte result describing the diagnosis and the distance to a fault.
   */
  async cableTest(port: number): Promise<CableTestResult> {
    const { tlvs } = await this.authedSet([
      { type: TlvType.CABLE_TEST, value: serializeCableTestRequest(port) },
    ]);
    const t = tlvs.find((x) => x.type === TlvType.CABLE_TEST && x.value.length === 6);
    if (!t) throw new Error('cable test: no result TLV in response');
    return parseCableTestResult(t.value);
  }

  // ---------- PoE ----------

  async getPoeSystem(): Promise<PoeSystem> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.POE_SYSTEM, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.POE_SYSTEM);
    if (!t) throw new Error('switch does not appear to support PoE (no TLV 13568 in response)');
    return parsePoeSystem(t.value);
  }

  /** Set the global PoE budget, in 0.1 W units (e.g. 650 = 65 W). */
  async setPoeSystemLimit(limitDeciwatt: number): Promise<void> {
    await this.authedSet([{ type: TlvType.POE_SYSTEM, value: serializePoeSystemLimit(limitDeciwatt) }]);
  }

  async getPoePorts(): Promise<PoePortConfig[]> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.POE_PORT, value: Buffer.alloc(0) }]);
    return tlvs.filter((t) => t.type === TlvType.POE_PORT && t.value.length >= 14).map((t) => parsePoePort(t.value));
  }

  async setPoePort(p: {
    port: number;
    enabled: boolean;
    priority: PoePriority;
    limitDeciwatt: number;
  }): Promise<void> {
    await this.authedSet([{ type: TlvType.POE_PORT, value: serializePoePort(p) }]);
  }

  async getPoeExtend(): Promise<PoeExtendEntry[]> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.POE_EXTEND, value: Buffer.alloc(0) }]);
    return tlvs.filter((t) => t.type === TlvType.POE_EXTEND && t.value.length >= 2).map((t) => parsePoeExtend(t.value));
  }

  async setPoeExtend(entry: PoeExtendEntry): Promise<void> {
    await this.authedSet([{ type: TlvType.POE_EXTEND, value: serializePoeExtend(entry) }]);
  }

  async getPoeRecoveryEnabled(): Promise<boolean> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.POE_RECOVERY_GLOBAL, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.POE_RECOVERY_GLOBAL);
    return t ? parseBool(t.value) : false;
  }

  async setPoeRecoveryEnabled(enabled: boolean): Promise<void> {
    await this.authedSet([{ type: TlvType.POE_RECOVERY_GLOBAL, value: serializeBool(enabled) }]);
  }

  // ---------- Full config + lifecycle ----------

  /**
   * Download the official binary config backup — the same blob the Easy Smart
   * Configuration Utility saves via "Backup Config" (TLV 768, the raw config
   * image). Requires a successful login(). On 2023+ firmware the export only
   * works over the RSA session transport: if login() didn't open one, this
   * opens a temporary session, and clears it and logs back in over the legacy
   * transport afterwards, so the switch is never left session-locked.
   * The reply arrives fragmented (fragmentOffset counts down to 0); the
   * transport waits for every fragment and throws if any is missing.
   */
  async backupConfig(): Promise<Buffer> {
    const temporary = !this.useSession() && (await this.startSession());
    try {
      await this.refreshToken();
      const { tlvs } = await this.query(
        OpCode.LOGIN,
        [...this.loginTlvs(), { type: TlvType.SYSTEM_CONFIG_GET, value: Buffer.alloc(0) }],
        this.useSession(),
        FRAGMENT_SETTLE_MS,
      );
      const chunks = tlvs.filter((t) => t.type === TlvType.SYSTEM_CONFIG_GET).map((t) => t.value);
      if (!chunks.length) throw new Error('config export: no data TLV in response');
      return Buffer.concat(chunks);
    } finally {
      if (temporary) {
        await this.logout();
        await this.legacyLogin();
      }
    }
  }

  /**
   * Clear the switch's RSA session state so legacy (static RC4) clients can
   * talk to it again. While an RSA session is active the switch ignores legacy
   * traffic for minutes to hours; sending the session-key TLV with an empty
   * value unlocks it immediately (the switch ACKs with 4098, same as a real
   * handshake). Verified live on TL-SG105E and TL-SG108E.
   * This is sent even when this client has no session, so it also clears a
   * lock left behind by another process. Throws if the switch doesn't ACK it;
   * local session state is reset either way.
   */
  async logout(): Promise<void> {
    try {
      // Sent static-encrypted: the TLV 528 handshake path accepts the legacy
      // cipher even while the switch is session-locked (new clients need in).
      await this.sendSessionClear();
    } finally {
      this.clearLocalSession();
    }
  }

  async getFullConfig(): Promise<SwitchConfig> {
    const info = await this.getInfo();
    const ports = await this.getPorts();
    const vlans = await this.getVlans();
    const pvids = await this.getPvids();
    const vlanEnabled = await this.getVlanEnabled();
    const igmpSnooping = await this.getIgmpSnooping();
    const qos = await this.getQos();
    const mirror = await this.getMirror();
    const loopPrevention = await this.getLoopPrevention();
    const statistics = await this.getPortStatistics();
    return { info, ports, vlans, pvids, vlanEnabled, igmpSnooping, qos, mirror, loopPrevention, statistics };
  }

  async save(): Promise<void> {
    await this.authedSet([{ type: TlvType.SAVE, value: Buffer.from([1]) }]);
  }

  async reboot(): Promise<void> {
    await this.authedSet([{ type: TlvType.REBOOT, value: Buffer.from([1]) }]);
  }

  /** Clear any active RSA session (best effort), then close the sockets. */
  async close(): Promise<void> {
    const t = this.transport;
    if (!t) return;
    if (this.useSession()) {
      try {
        await this.logout();
      } catch {
        // Closing must not fail because the switch is unreachable.
      }
    }
    t.close();
    if (this.transport === t) this.transport = undefined;
  }
}
