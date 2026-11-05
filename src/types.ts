export enum OpCode {
  DISCOVERY = 0,
  GET = 1,
  SET = 2,
  LOGIN = 3,
  RETURN = 4,
  READ5 = 5,
}

/** Transport security negotiated at login. */
export type SecurityMode = 'rsa-big' | 'rsa-small' | 'legacy';

/**
 * How login() picks a transport.
 * - 'legacy' (default): static RC4 only. Never puts the switch into RSA
 *   session mode, so legacy-only tools keep working.
 * - 'auto': try an RSA session (1024-bit, then 64-bit), fall back to legacy.
 * - 'rsa': require an RSA session; login() throws if the switch refuses it.
 * backupConfig() opens a temporary RSA session on its own when needed.
 */
export type SecurityPreference = 'legacy' | 'auto' | 'rsa';

export enum TlvType {
  // System info
  TYPE = 1,
  HOSTNAME = 2,
  MAC = 3,
  IP_ADDR = 4,
  IP_MASK = 5,
  GATEWAY = 6,
  FIRMWARE = 7,
  HARDWARE = 8,
  DHCP = 9,
  NUM_PORTS = 10,
  MANAGEMENT_VLAN = 11,
  LED_STATUS = 12,
  AUTO_SAVE = 13,
  IS_FACTORY = 14,
  FLASH_TYPE = 15,
  // Authentication
  USERNAME = 512,
  PASSWORD_OLD = 513,
  PASSWORD = 514,
  PASSWORD_NEW = 515,
  RSA_KEY = 528,
  // System actions
  SYSTEM_CONFIG_GET = 768,
  SYSTEM_CONFIG_SET = 769,
  REBOOT = 773,
  SYSTEM_RESET = 1280,
  SYSTEM_UPGRADE = 1536,
  SAVE = 2304,
  GET_TOKEN_ID = 2305,
  // Ports
  PORTS = 4096,
  IGMP_SNOOPING = 4352,
  IGMP_SUPPRESS = 4354,
  TRUNK = 4608,
  // VLAN (MTU VLAN / 802.1Q / port-based)
  MTU_VLAN = 8192,
  PORT_VLAN_ENABLED = 8448,
  PORT_VLAN_ENTRY = 8449,
  PORT_VLAN_COUNT = 8450,
  VLAN_ENABLED = 8704,
  VLAN = 8705,
  PVID = 8706,
  VLAN_FILLER = 8707,
  MTU_VLAN_MANAGEMENT_ENABLED = 8708,
  MTU_VLAN_MANAGEMENT_PORTS = 8709,
  PORT_VLAN_MANAGEMENT_ENABLED = 8710,
  PORT_VLAN_MANAGEMENT_PORTS = 8711,
  VLAN_8021Q_MANAGEMENT_ENABLED = 8712,
  VLAN_8021Q_MANAGEMENT_VLAN = 8713,
  // QoS
  QOS_MODE = 12288,
  QOS_PRIORITY = 12289,
  BANDWIDTH_INGRESS = 12544,
  BANDWIDTH_EGRESS = 12545,
  STORM_CONTROL = 12800,
  // PoE
  POE_SYSTEM = 13568,
  POE_PORT = 13824,
  POE_RECOVERY_GLOBAL = 14080,
  POE_RECOVERY_ENTRY = 14336,
  POE_EXTEND = 14592,
  // Monitoring
  PORT_STATISTICS = 16384,
  PORT_MIRROR = 16640,
  CABLE_TEST = 16896,
  LOOP_PREVENTION = 17152,
  END = 0xffff,
}

export enum PortSpeed {
  LINK_DOWN = 0,
  AUTO = 1,
  M10_HALF = 2,
  M10_FULL = 3,
  M100_HALF = 4,
  M100_FULL = 5,
  M1000_FULL = 6,
}

export enum FlowControl {
  OFF = 0,
  ON = 1,
}

export interface PacketHeader {
  version: number;
  opCode: OpCode;
  switchMac: Buffer;
  hostMac: Buffer;
  sequenceId: number;
  errorCode: number;
  checkLength: number;
  fragmentOffset: number;
  flag: number;
  tokenId: number;
  checksum: number;
}

export interface TlvEntry {
  type: number;
  value: Buffer;
}

export interface SwitchInfo {
  type: string;
  hostname: string;
  mac: string;
  ipAddress: string;
  subnetMask: string;
  gateway: string;
  firmware: string;
  hardware: string;
  dhcp: boolean;
  numPorts: number;
}

export interface PortConfig {
  port: number;
  enabled: boolean;
  lag: number;
  speed: PortSpeed;
  actualSpeed: PortSpeed;
  flowControl: FlowControl;
  actualFlowControl: FlowControl;
}

export interface PortStatistics {
  port: number;
  status: number;
  txGood: number;
  txBad: number;
  rxGood: number;
  rxBad: number;
}

export interface VlanConfig {
  vlanId: number;
  name: string;
  memberPorts: number[];
  taggedPorts: number[];
  untaggedPorts: number[];
}

export interface PvidConfig {
  port: number;
  pvid: number;
}

/** Per-port priority mapping for basic port-priority QoS (TLV 12289). */
export interface QosPriority {
  port: number;
  priority: number;
}

export interface QosConfig {
  mode: boolean;
  priorities: QosPriority[];
}

/** Parsed 10-byte PORT_MIRROR value. */
export interface MirrorConfig {
  enabled: boolean;
  mirrorPort: number;
  ingressPorts: number[];
  egressPorts: number[];
}

/** Bandwidth limit for a single direction on a single port. */
export interface BandwidthEntry {
  port: number;
  enabled: boolean;
  /** Rate in Kbps (0 = unlimited). */
  rateKbps: number;
}

export interface BandwidthConfig {
  ingress: BandwidthEntry[];
  egress: BandwidthEntry[];
}

export interface StormControlEntry {
  port: number;
  enabled: boolean;
  broadcastEnabled: boolean;
  multicastEnabled: boolean;
  unknownUnicastEnabled: boolean;
  /** Rate in Kbps (0 = unlimited when enabled is false). */
  rateKbps: number;
}

/**
 * System IP configuration. When dhcp is true the address fields may be ignored
 * by the switch (they are cleared in the write path to match the official app).
 */
export interface IpConfig {
  dhcp: boolean;
  ipAddress?: string;
  subnetMask?: string;
  gateway?: string;
  managementVlan?: number;
}

/** MTU-VLAN mode toggle + uplink port (1-based). */
export interface MtuVlanConfig {
  enabled: boolean;
  uplinkPort: number;
}

/** One entry in port-based VLAN mode: a VLAN id and its member ports. */
export interface PortVlanEntry {
  vlanId: number;
  memberPorts: number[];
}

export interface PortVlanConfig {
  enabled: boolean;
  entries: PortVlanEntry[];
  managementStatus: boolean;
  managementPorts: number[];
}

export type CableTestResultType =
  | 'no_cable'
  | 'normal'
  | 'open'
  | 'short'
  | 'open_short'
  | 'cross_cable';

export interface CableTestResult {
  port: number;
  type: CableTestResultType;
  /** Distance to fault in meters (0 when type is normal/no_cable). */
  distanceMeters: number;
}

/** Global PoE system counters (all power values in 0.1 W units). */
export interface PoeSystem {
  powerLimit: number;
  powerLimitMin: number;
  powerLimitMax: number;
  powerConsumption: number;
  powerRemain: number;
}

export enum PoePriority {
  HIGH = 0,
  MIDDLE = 1,
  LOW = 2,
}

/**
 * PoE per-port config and live readings.
 * Limit/power/current/voltage/pdClass are in 0.1 W or similar sub-units — 330 = "auto".
 */
export interface PoePortConfig {
  port: number;
  enabled: boolean;
  priority: PoePriority;
  /** Power limit in 0.1 W units. 330 = Auto, 40/70/154/300 = classes 1-4. */
  limitDeciwatt: number;
  powerDeciwatt: number;
  currentMilliamp: number;
  voltageDecivolt: number;
  pdClassDeciwatt: number;
  powerStatus: number;
}

export interface PoeExtendEntry {
  port: number;
  enabled: boolean;
}

export interface SwitchConfig {
  info: SwitchInfo;
  ports: PortConfig[];
  vlans: VlanConfig[];
  pvids: PvidConfig[];
  vlanEnabled: boolean;
  igmpSnooping: boolean;
  qos: QosConfig;
  mirror: MirrorConfig;
  loopPrevention: boolean;
  statistics: PortStatistics[];
}

export interface DiscoveredSwitch {
  info: SwitchInfo;
  sourceInterface: string;
  sourceIp: string;
}

export interface SwitchClientOptions {
  switchMac: string;
  interface?: string;
  username?: string;
  password?: string;
  timeout?: number;
  security?: SecurityPreference;
}
