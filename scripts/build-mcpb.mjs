#!/usr/bin/env node
// Build the MCPB bundle + Smithery stdio release payload for @saihm/mcp-server-pro.
//
// Why this exists: the bundle published for the standards client in June was hand-authored and is
// not reproducible from source. This script makes the -pro artifact regenerable, so what is
// published always matches what is built.
//
//   npm run build:mcpb   ->  dist-mcpb/saihm-mcp-server-pro.mcpb
//                            dist-mcpb/payload.json   (Smithery StdioDeployPayload)
//
// An .mcpb is a zip of a descriptor, not a packaged runtime: the host reads
// server.mcp_config and launches `npx -y @saihm/mcp-server-pro` itself.
//
// The tool list is enumerated from the built server over stdio rather than hand-maintained, so it
// cannot drift. That enumeration is contained: HOME is redirected to a scratch dir and
// SAIHM_ENDPOINT_URL is pointed at a dead local port, so a build can never reach the live operator
// or trigger onboarding. tools/list does not call the endpoint; the containment is belt-and-braces.

import { spawn } from 'node:child_process';
import { deflateRawSync } from 'node:zlib';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'dist-mcpb');
const SERVER = join(ROOT, 'dist', 'server.js');

const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
const NPM_NAME = pkg.name;
const REPO = 'https://github.com/SAIHM-Admin/saihm-mcp-server-pro';
// Bundle identity follows the repo / Smithery server slug, not the unscoped npm name — that is the
// convention the standards bundle already uses (`saihm-mcp`, matching `saihm/saihm-mcp`).
const SHORT = REPO.split('/').pop(); // saihm-mcp-server-pro

if (!existsSync(SERVER)) {
  console.error(`missing ${SERVER} — run \`npm run build\` first`);
  process.exit(1);
}

// ---------------------------------------------------------------- tool enumeration

function enumerateTools() {
  return new Promise((resolve, reject) => {
    const home = mkdtempSync(join(tmpdir(), 'saihm-mcpb-'));
    const env = { ...process.env, HOME: home, SAIHM_ENDPOINT_URL: 'http://127.0.0.1:9/mcp' };
    const p = spawn(process.execPath, [SERVER], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('error', reject);

    const send = (o) => p.stdin.write(JSON.stringify(o) + '\n');
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'build-mcpb', version: '1' } } });
    setTimeout(() => {
      send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    }, 400);
    setTimeout(() => {
      p.kill('SIGTERM');
      rmSync(home, { recursive: true, force: true });
      const msgs = out.split('\n').filter(Boolean)
        .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      const serverInfo = msgs.find((m) => m.id === 1)?.result?.serverInfo;
      const tools = msgs.find((m) => m.id === 2)?.result?.tools;
      if (!serverInfo || !Array.isArray(tools) || tools.length === 0) {
        reject(new Error(`tool enumeration failed. stderr: ${err.slice(0, 400)}`));
        return;
      }
      resolve({ serverInfo, tools });
    }, 1800);
  });
}

// ---------------------------------------------------------------- minimal zip writer
// No `zip` binary on the build host and no dependency is worth adding for two files.

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

// DOS date/time. Fixed epoch so the same inputs always yield a byte-identical bundle.
const DOS_TIME = 0;      // 00:00:00
const DOS_DATE = 0x2821; // 2000-01-01

function zip(entries) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name, 'utf8');
    const comp = deflateRawSync(data, { level: 9 });
    const crc = crc32(data);

    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);           // version needed
    lfh.writeUInt16LE(0, 6);            // flags
    lfh.writeUInt16LE(8, 8);            // deflate
    lfh.writeUInt16LE(DOS_TIME, 10);
    lfh.writeUInt16LE(DOS_DATE, 12);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(comp.length, 18);
    lfh.writeUInt32LE(data.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    lfh.writeUInt16LE(0, 28);
    locals.push(lfh, nameBuf, comp);

    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE(20, 4);           // version made by
    cdh.writeUInt16LE(20, 6);           // version needed
    cdh.writeUInt16LE(0, 8);
    cdh.writeUInt16LE(8, 10);
    cdh.writeUInt16LE(DOS_TIME, 12);
    cdh.writeUInt16LE(DOS_DATE, 14);
    cdh.writeUInt32LE(crc, 16);
    cdh.writeUInt32LE(comp.length, 20);
    cdh.writeUInt32LE(data.length, 24);
    cdh.writeUInt16LE(nameBuf.length, 28);
    cdh.writeUInt32LE(0, 38);           // external attrs
    cdh.writeUInt32LE(offset, 42);
    central.push(cdh, nameBuf);

    offset += lfh.length + nameBuf.length + comp.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

// ---------------------------------------------------------------- build

// -pro is zero-secret: it generates its own master secret locally and self-onboards, so nothing is
// required. The single optional field only repoints the operator endpoint.
const CONFIG_SCHEMA = {
  type: 'object',
  required: [],
  properties: {
    saihm_endpoint_url: {
      type: 'string',
      title: 'SAIHM operator endpoint URL',
      description: 'Optional. Set only to point at a different SAIHM operator; defaults to https://saihm.coti.global/mcp.',
    },
  },
};

const SHIM = `// @saihm/mcp-server-pro bundle launcher.
// At runtime the host uses server.mcp_config (npx -y ${NPM_NAME});
// this file exists only to satisfy the MCPB entry_point requirement.
import { spawnSync } from 'node:child_process';
const r = spawnSync('npx', ['-y', '${NPM_NAME}'], { stdio: 'inherit' });
process.exit(r.status ?? 0);
`;

const { serverInfo, tools } = await enumerateTools();

const manifest = {
  manifest_version: '0.3',
  name: SHORT,
  display_name: 'SAIHM Pro',
  version: pkg.version,
  description: pkg.description,
  keywords: ['memory', 'persistent-memory', 'encryption', 'post-quantum', 'non-custodial', 'agent-memory', 'mcp'],
  author: { name: 'SAIHM' },
  license: pkg.license,
  homepage: pkg.homepage,
  documentation: REPO,
  repository: { type: 'git', url: REPO },
  icon: `https://raw.githubusercontent.com/SAIHM-Admin/saihm-mcp-server-pro/main/assets/icon.png`,
  server: {
    type: 'node',
    entry_point: 'server/index.js',
    mcp_config: {
      command: 'npx',
      args: ['-y', NPM_NAME],
      env: { SAIHM_ENDPOINT_URL: '${user_config.saihm_endpoint_url}' },
    },
  },
  user_config: {
    saihm_endpoint_url: {
      type: 'string',
      title: CONFIG_SCHEMA.properties.saihm_endpoint_url.title,
      description: CONFIG_SCHEMA.properties.saihm_endpoint_url.description,
      required: false,
      default: 'https://saihm.coti.global/mcp',
    },
  },
  tools: tools.map((t) => ({ name: t.name, description: t.description })),
};

mkdirSync(OUT, { recursive: true });

const bundle = zip([
  { name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest, null, 2) + '\n', 'utf8') },
  { name: 'server/index.js', data: Buffer.from(SHIM, 'utf8') },
]);
const bundlePath = join(OUT, `${SHORT}.mcpb`);
writeFileSync(bundlePath, bundle);

// serverCard is what populates the tool list on the listing page. Omitting it is why the
// standards listing shows `tools: null`.
const payload = {
  type: 'stdio',
  runtime: 'node',
  configSchema: CONFIG_SCHEMA,
  serverCard: { serverInfo, tools },
};
const payloadPath = join(OUT, 'payload.json');
writeFileSync(payloadPath, JSON.stringify(payload, null, 2) + '\n');

console.log(`bundle   ${bundlePath} (${bundle.length} bytes)`);
console.log(`payload  ${payloadPath}`);
console.log(`server   ${serverInfo.name} ${serverInfo.version}`);
console.log(`tools    ${tools.length}: ${tools.map((t) => t.name).join(', ')}`);
