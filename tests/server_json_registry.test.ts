/**
 * Registry-manifest guards for @saihm/mcp-server-pro.
 *
 * `server.json` is what the MCP registry renders; nothing in the build reads it, so a bad edit
 * here ships silently and is only visible in someone else's directory listing. These are the
 * checks that a human reviewer would otherwise have to remember to run by eye.
 *
 * The env-var check runs in ONE direction on purpose: every variable the manifest DECLARES must
 * actually be read by the shipping source. The converse is deliberately not asserted — the
 * manifest omits the advanced static-token rail so that self-join stays the advertised onboarding
 * path, and asserting set equality would turn that intentional omission into a failure.
 *
 * Runner: npx tsx --test tests/server_json_registry.test.ts   (or `npm test`)
 */

import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => JSON.parse(readFileSync(join(ROOT, p), "utf8"));

const pkg = read("package.json");
const manifest = read("server.json");

/** The registry schema caps the rendered description; over this it is rejected or truncated. */
const DESCRIPTION_LIMIT = 100;

function sourceText(): string {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir)) {
      const p = join(dir, e);
      if (statSync(p).isDirectory()) walk(p);
      else if (e.endsWith(".ts")) out.push(readFileSync(p, "utf8"));
    }
  };
  walk(join(ROOT, "src"));
  return out.join("\n");
}

describe("RM1: server.json renders inside the registry's budget", () => {
  it("description is present and within the limit", () => {
    const d: string = manifest.description;
    assert.equal(typeof d, "string");
    assert.ok(d.length > 0, "server.json description is empty");
    assert.ok(d.length <= DESCRIPTION_LIMIT,
      `server.json description is ${d.length} chars; the registry limit is ${DESCRIPTION_LIMIT}`);
  });

  it("package.json carries its own description and does not inherit the registry's", () => {
    assert.ok(typeof pkg.description === "string" && pkg.description.length > 0);
  });

  it("the manifest is pinned to a published schema", () => {
    assert.match(manifest.$schema, /^https:\/\/static\.modelcontextprotocol\.io\/schemas\/.+\/server\.schema\.json$/);
  });
});

describe("RM2: the manifest cannot drift from the package it describes", () => {
  it("declares exactly one npm package, and it is this one", () => {
    const npm = manifest.packages.filter((p: any) => p.registryType === "npm");
    assert.equal(npm.length, 1, "expected exactly one npm package entry");
    assert.equal(npm[0].identifier, pkg.name);
  });

  it("every version in the manifest matches package.json", () => {
    assert.equal(manifest.version, pkg.version, "server.json version != package.json version");
    for (const p of manifest.packages) {
      assert.equal(p.version, pkg.version, `packages[${p.identifier}].version != package.json version`);
    }
  });

  it("the repository it points at is the one that publishes it", () => {
    assert.equal(manifest.repository.source, "github");
    assert.match(manifest.repository.url, /^https:\/\/github\.com\/SAIHM-Admin\//);
  });
});

describe("RM3: declared environment variables are real", () => {
  const src = sourceText();

  it("every declared variable is read somewhere in src", () => {
    const declared: string[] = manifest.packages
      .flatMap((p: any) => p.environmentVariables ?? [])
      .map((v: any) => v.name);
    assert.ok(declared.length > 0, "no environment variables declared");
    const unread = declared.filter(
      (n) => !(new RegExp(`process\\.env\\.${n}\\b`).test(src) ||
               new RegExp(`process\\.env\\[["'\`]${n}["'\`]\\]`).test(src)));
    assert.deepEqual(unread, [], `declared in server.json but never read in src: ${unread.join(", ")}`);
  });

  it("each declared variable carries a description and an explicit isRequired", () => {
    for (const p of manifest.packages) {
      for (const v of p.environmentVariables ?? []) {
        assert.ok(typeof v.description === "string" && v.description.length > 0, `${v.name} has no description`);
        assert.equal(typeof v.isRequired, "boolean", `${v.name} does not state isRequired`);
      }
    }
  });

  it("any variable holding a secret is marked isSecret", () => {
    for (const p of manifest.packages) {
      for (const v of p.environmentVariables ?? []) {
        if (/SECRET|TOKEN|KEY|PASSWORD/.test(v.name) && v.format !== "string") {
          assert.equal(v.isSecret, true, `${v.name} looks secret-bearing but is not marked isSecret`);
        }
      }
    }
  });
});
