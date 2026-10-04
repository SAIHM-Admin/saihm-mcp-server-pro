// Tool arguments as hosts actually send them.
//
// A host that fills every field of a tool's schema has no way to leave one out. OpenAI's strict function calling, and the
// hosts that convert an MCP schema to it, send null, an empty string, or an object of empty strings for each field the
// model did not choose. A client SDK that calls a tool with no parameters may leave `arguments` out of the request
// altogether, which the protocol allows. Each of these used to fail the call with an input error; in recall, an object of
// empty strings read as a half-specified shared read, so such a host could not load its own memories at all.
//
// Both mappings run before validation and change nothing a host is shown: the advertised schemas are the plain ones, and
// a value of the wrong type is still refused.
import { z } from 'zod';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';

const isBlankScalar = (v: unknown): boolean =>
  v === undefined || v === null || (typeof v === 'string' && v.trim() === '');

/**
 * True for what a host sends in place of leaving an optional field out: null or a blank string, and, for a field that takes
 * an OBJECT, an object every field of which is one of those. One level only: an object holding an object is a value, and
 * validation decides what it is worth. An object sent for a field that takes no object is a wrong type, and stays one.
 */
export function isBlankInput(v: unknown, takesObject = false): boolean {
  if (isBlankScalar(v)) return true;
  if (takesObject && typeof v === 'object' && v !== null && !Array.isArray(v)) return Object.values(v).every(isBlankScalar);
  return false;
}

/** An optional tool field that reads a blank value (see isBlankInput) as absent, so the tool does what it does without it. */
export function optionalInput<T extends z.ZodType>(schema: T) {
  const takesObject = schema instanceof z.ZodObject;
  return z.preprocess((v) => (isBlankInput(v, takesObject) ? undefined : v), schema.optional());
}

/** A tools/call request whose `arguments` is left out or null, given an empty object in its place; any other message as it came. */
export function withToolArguments(message: JSONRPCMessage): JSONRPCMessage {
  if (!('method' in message) || message.method !== 'tools/call' || !('id' in message)) return message;
  const params: unknown = message.params;
  if (typeof params !== 'object' || params === null || Array.isArray(params)) return message;
  const { arguments: args } = params as { arguments?: unknown };
  if (args !== undefined && args !== null) return message;
  return { ...message, params: { ...params, arguments: {} } } as JSONRPCMessage;
}

/**
 * Applies withToolArguments to every message the transport delivers. The SDK validates `arguments` as an object even for
 * a tool that takes no input, and refuses null before any tool runs. The wrap is installed in start(), which the server
 * calls only after setting its message handler, so no message is delivered unwrapped.
 */
export function acceptAbsentToolArguments<T extends Transport>(transport: T): T {
  const start = transport.start.bind(transport);
  transport.start = async () => {
    const deliver = transport.onmessage;
    if (deliver) transport.onmessage = (message, extra) => deliver(withToolArguments(message), extra);
    return start();
  };
  return transport;
}
