# tplink-escp

TypeScript library for the TP-Link Easy Smart Configuration Protocol (ESCP).
Cross-platform Node.js replacement for the Windows-only Java Easy Smart Configuration Utility.

Supports TL-SG105E / SG108E / SG116E / SG1016DE / SG1024DE / SG108PE and similar.

Live-tested on a TL-SG1024DE hardware v7.0 running firmware `1.0.0 Build 20230616 Rel.34205`.

## Install

```bash
npm install tplink-escp
```

## Discover switches

```ts
import { discoverSwitches } from 'tplink-escp';

const switches = await discoverSwitches({ timeout: 2000 });
for (const s of switches) {
  console.log(s.info.hostname, s.info.mac, s.info.ipAddress);
}
```

## Read and modify config

```ts
import { SwitchClient } from 'tplink-escp';

const client = new SwitchClient({
  switchMac: '00:11:22:33:44:55',
  username: 'admin',
  password: 'adminpass',
});

await client.login();
const info = await client.getInfo();
const ports = await client.getPorts();
const vlans = await client.getVlans();
const pvids = await client.getPvids();
const bandwidth = await client.getBandwidthControl();
const storm = await client.getStormControl();

// VLANs must be set one-at-a-time (firmware bug).
await client.setVlan({
  vlanId: 10,
  name: 'office',
  memberPorts: [1, 2, 3],
  taggedPorts: [1],
  untaggedPorts: [2, 3],
});

await client.save();
client.close();
```

## Supported operations

- Discovery and login
- System info, hostname, LED status, DHCP/static IP config, credential changes
- Port config and port statistics
- 802.1Q VLANs, PVIDs, management VLAN, MTU VLAN, and port-based VLAN mode
- IGMP snooping and report suppression
- QoS mode and per-port priority
- Ingress/egress bandwidth control
- Storm control
- Port mirroring
- Loop prevention
- Cable test
- PoE system/port/extend/recovery helpers for PoE-capable models
- Save, reboot, and factory reset actions

## Notes

- UDP broadcast on ports 29808/29809. May require elevated permissions on some OSes.
- Encryption: RC4-variant with a hardcoded key shipped in every firmware - this is not security.
- Set VLANs one at a time to avoid corrupted VLAN names.
- Always leave every port in at least one VLAN.
- The client matches replies by sequence ID to avoid stale UDP responses being parsed as later requests.
- Storm-control TLVs are 9 bytes on TL-SG1024DE v7.0: port, enabled flag, three traffic-type flags, and a 4-byte rate.
- PoE helpers return empty data or throw an unsupported error on non-PoE switches.

## Build

```bash
npm install
npm run build
npm test
```

## MCP server (stdio)

This repository also ships a local MCP server entrypoint that wraps core switch
discovery/configuration operations with tool calls.

```bash
npm install
npm run build
npm run mcp:start
```

The MCP server name is `tplink-mcp-server` and includes tool names prefixed with
`tplink_` (for example `tplink_discover_switches`, `tplink_get_switch_info`,
`tplink_get_full_config`, `tplink_set_vlan`, and `tplink_save_config`).
