// A tool's advertised input schema as a host with strict function calling sees it (OpenAI strict mode, and the hosts that
// convert an MCP schema to it): every property required, no other property allowed, at every level. Such a host cannot
// leave a field out; it can only send what the schema allows. The blank choice of a field is what the host sends when the
// model does not choose it: "" for a string (it must be one of an enum's values and match a pattern), false for a
// boolean, and an object of blanks for an object. Not a test file: the tests that use it import it.
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/ajv';

type Schema = { type?: string; properties?: Record<string, Schema>; required?: string[]; enum?: unknown[]; pattern?: string; [k: string]: unknown };

/** The schema with every property required and additionalProperties false, recursively. */
export function strictSchema(s: Schema): Schema {
  if (s.type !== 'object') return s;
  const properties = Object.fromEntries(Object.entries(s.properties ?? {}).map(([k, v]) => [k, strictSchema(v)]));
  return { ...s, properties, required: Object.keys(properties), additionalProperties: false };
}

/** The blank choice of one field. */
export function blankChoice(s: Schema): unknown {
  if (s.type === 'boolean') return false;
  if (s.type === 'object') return Object.fromEntries(Object.entries(s.properties ?? {}).map(([k, v]) => [k, blankChoice(v)]));
  return '';
}

/** Arguments for a strict host: the given values, and the blank choice for every other field. */
export function strictArguments(inputSchema: Schema, given: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(inputSchema.properties ?? {}).map(([k, v]) => [k, k in given ? given[k] : blankChoice(v)]));
}

/** Null when `args` is valid under the strict form of `inputSchema`, else the validator's message. */
export function strictViolation(inputSchema: Schema, args: unknown): string | null {
  const r = new AjvJsonSchemaValidator().getValidator(strictSchema(inputSchema) as never)(args);
  return r.valid ? null : (r.errorMessage ?? 'invalid');
}
