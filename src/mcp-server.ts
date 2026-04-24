import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { SwitchClient } from './client.js';
import { discoverSwitches } from './discovery.js';
import { PvidConfig, VlanConfig } from './types.js';

const server = new McpServer({
  name: 'tplink-mcp-server',
  version: '0.1.0',
});

const responseFormatSchema = z.enum(['markdown', 'json']).default('json');

const connectionInputSchema = {
  switch_mac: z.string().min(11).max(17).describe('Target switch MAC (for example 00:11:22:33:44:55).'),
  username: z.string().min(1).default('admin').describe('Switch admin username.'),
  password: z.string().min(1).default('admin').describe('Switch admin password.'),
  interface: z.string().min(1).optional().describe('Optional network interface to bind discovery/control UDP sockets.'),
  timeout_ms: z.number().int().min(250).max(30000).default(2000).describe('UDP response timeout in milliseconds.'),
  response_format: responseFormatSchema.describe('Response format: json (default) or markdown.'),
};

interface SwitchConnectionInput {
  switch_mac: string;
  username: string;
  password: string;
  interface?: string;
  timeout_ms: number;
  response_format: 'markdown' | 'json';
}

function toStructuredContent(value: unknown): Record<string, unknown> {
  return value as Record<string, unknown>;
}

function formatText(title: string, payload: unknown, responseFormat: 'markdown' | 'json'): string {
  if (responseFormat === 'markdown') {
    return `# ${title}\n\n\`\`\`json\n${JSON.stringify(payload, null, 2)}\n\`\`\``;
  }
  return JSON.stringify(payload, null, 2);
}

function formatError(error: unknown, action: string): string {
  const base = error instanceof Error ? error.message : String(error);
  if (/timed out/i.test(base)) {
    return `${action} failed: request timed out. Verify interface/switch MAC reachability and try a higher timeout_ms.`;
  }
  if (/support PoE/i.test(base)) {
    return `${action} failed: this model likely does not support PoE APIs.`;
  }
  return `${action} failed: ${base}`;
}

async function withSwitchClient<T>(
  params: SwitchConnectionInput,
  action: string,
  run: (client: SwitchClient) => Promise<T>,
): Promise<{ ok: true; data: T } | { ok: false; errorText: string }> {
  const client = new SwitchClient({
    switchMac: params.switch_mac,
    username: params.username,
    password: params.password,
    interface: params.interface,
    timeout: params.timeout_ms,
  });

  try {
    await client.login();
    const data = await run(client);
    return { ok: true, data };
  } catch (error) {
    return { ok: false, errorText: formatError(error, action) };
  } finally {
    client.close();
  }
}

server.registerTool(
  'tplink_discover_switches',
  {
    title: 'Discover TP-Link switches',
    description: 'Broadcast discovery requests and list switches visible on the local network.',
    inputSchema: {
      interface: z.string().min(1).optional().describe('Optional network interface to bind the UDP discovery socket.'),
      timeout_ms: z.number().int().min(250).max(30000).default(2000).describe('Discovery wait time in milliseconds.'),
      limit: z.number().int().min(1).max(100).default(20).describe('Maximum items to return.'),
      offset: z.number().int().min(0).default(0).describe('Pagination offset for results.'),
      response_format: responseFormatSchema.describe('Response format: json (default) or markdown.'),
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async ({ interface: networkInterface, timeout_ms, limit, offset, response_format }) => {
    try {
      const allSwitches = await discoverSwitches({ interface: networkInterface, timeout: timeout_ms });
      const page = allSwitches.slice(offset, offset + limit);
      const output = {
        total_count: allSwitches.length,
        count: page.length,
        offset,
        has_more: offset + page.length < allSwitches.length,
        next_offset: offset + page.length < allSwitches.length ? offset + page.length : null,
        switches: page,
      };
      return {
        content: [{ type: 'text', text: formatText('TP-Link Discovery Results', output, response_format) }],
        structuredContent: toStructuredContent(output),
      };
    } catch (error) {
      return {
        isError: true,
        content: [{ type: 'text', text: formatError(error, 'Discovery') }],
      };
    }
  },
);

server.registerTool(
  'tplink_get_switch_info',
  {
    title: 'Get switch system info',
    description: 'Authenticate to one switch and read system identity/network info.',
    inputSchema: connectionInputSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async (params: SwitchConnectionInput) => {
    const result = await withSwitchClient(params, 'Get switch info', (client) => client.getInfo());
    if (!result.ok) {
      return { isError: true, content: [{ type: 'text', text: result.errorText }] };
    }
    return {
      content: [{ type: 'text', text: formatText('Switch Info', result.data, params.response_format) }],
      structuredContent: toStructuredContent(result.data),
    };
  },
);

server.registerTool(
  'tplink_get_ports',
  {
    title: 'Get port configuration',
    description: 'Read per-port link/admin/speed settings from one switch.',
    inputSchema: connectionInputSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async (params: SwitchConnectionInput) => {
    const result = await withSwitchClient(params, 'Get ports', (client) => client.getPorts());
    if (!result.ok) {
      return { isError: true, content: [{ type: 'text', text: result.errorText }] };
    }
    const output = { count: result.data.length, ports: result.data };
    return {
      content: [{ type: 'text', text: formatText('Port Configuration', output, params.response_format) }],
      structuredContent: toStructuredContent(output),
    };
  },
);

server.registerTool(
  'tplink_get_vlans',
  {
    title: 'Get VLAN configuration',
    description: 'Read 802.1Q VLAN entries from one switch.',
    inputSchema: connectionInputSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async (params: SwitchConnectionInput) => {
    const result = await withSwitchClient(params, 'Get VLANs', (client) => client.getVlans());
    if (!result.ok) {
      return { isError: true, content: [{ type: 'text', text: result.errorText }] };
    }
    const output = { count: result.data.length, vlans: result.data };
    return {
      content: [{ type: 'text', text: formatText('VLAN Configuration', output, params.response_format) }],
      structuredContent: toStructuredContent(output),
    };
  },
);

server.registerTool(
  'tplink_get_full_config',
  {
    title: 'Get full switch configuration',
    description: 'Read a broad switch configuration snapshot (info, ports, VLANs, PVIDs, QoS, mirror, stats).',
    inputSchema: connectionInputSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async (params: SwitchConnectionInput) => {
    const result = await withSwitchClient(params, 'Get full config', (client) => client.getFullConfig());
    if (!result.ok) {
      return { isError: true, content: [{ type: 'text', text: result.errorText }] };
    }
    return {
      content: [{ type: 'text', text: formatText('Full Switch Configuration', result.data, params.response_format) }],
      structuredContent: toStructuredContent(result.data),
    };
  },
);

server.registerTool(
  'tplink_set_vlan',
  {
    title: 'Set one VLAN entry',
    description: 'Create or update exactly one 802.1Q VLAN entry on a switch.',
    inputSchema: {
      ...connectionInputSchema,
      vlan: z.object({
        vlanId: z.number().int().min(1).max(4094),
        name: z.string().max(32),
        memberPorts: z.array(z.number().int().min(1).max(32)).default([]),
        taggedPorts: z.array(z.number().int().min(1).max(32)).default([]),
        untaggedPorts: z.array(z.number().int().min(1).max(32)).default([]),
      }).strict(),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async ({ vlan, ...params }: SwitchConnectionInput & { vlan: VlanConfig }) => {
    const result = await withSwitchClient(params, 'Set VLAN', async (client) => {
      await client.setVlan(vlan);
      return { updated: true, vlan };
    });
    if (!result.ok) {
      return { isError: true, content: [{ type: 'text', text: result.errorText }] };
    }
    return {
      content: [{ type: 'text', text: formatText('VLAN Updated', result.data, params.response_format) }],
      structuredContent: toStructuredContent(result.data),
    };
  },
);

server.registerTool(
  'tplink_set_pvids',
  {
    title: 'Set PVID mappings',
    description: 'Set one or more port PVID mappings on a switch.',
    inputSchema: {
      ...connectionInputSchema,
      pvids: z.array(
        z.object({
          port: z.number().int().min(1).max(32),
          pvid: z.number().int().min(1).max(4094),
        }).strict(),
      ).min(1),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async ({ pvids, ...params }: SwitchConnectionInput & { pvids: PvidConfig[] }) => {
    const result = await withSwitchClient(params, 'Set PVIDs', async (client) => {
      await client.setPvids(pvids);
      return { updated: true, count: pvids.length, pvids };
    });
    if (!result.ok) {
      return { isError: true, content: [{ type: 'text', text: result.errorText }] };
    }
    return {
      content: [{ type: 'text', text: formatText('PVIDs Updated', result.data, params.response_format) }],
      structuredContent: toStructuredContent(result.data),
    };
  },
);

server.registerTool(
  'tplink_save_config',
  {
    title: 'Save running config',
    description: 'Persist current running configuration to non-volatile storage on the switch.',
    inputSchema: connectionInputSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  async (params: SwitchConnectionInput) => {
    const result = await withSwitchClient(params, 'Save config', async (client) => {
      await client.save();
      return { saved: true };
    });
    if (!result.ok) {
      return { isError: true, content: [{ type: 'text', text: result.errorText }] };
    }
    return {
      content: [{ type: 'text', text: formatText('Config Saved', result.data, params.response_format) }],
      structuredContent: toStructuredContent(result.data),
    };
  },
);

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('tplink-mcp-server running on stdio');
}

main().catch((error) => {
  console.error(`tplink-mcp-server failed to start: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
