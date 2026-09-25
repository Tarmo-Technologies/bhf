// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { encodeFrame, FrameDecoder } from "../jsonRpc";

test("encodeFrame writes LSP-style content length framing", () => {
  const frame = encodeFrame({ jsonrpc: "2.0", id: 1, result: { ok: true } });

  assert.match(frame.toString("utf8"), /^Content-Length: \d+\r\n\r\n/);
  assert.match(frame.toString("utf8"), /"jsonrpc":"2.0"/);
});

test("FrameDecoder emits complete messages across chunk boundaries", () => {
  const messages: unknown[] = [];
  const decoder = new FrameDecoder((message) => messages.push(message));
  const frame = encodeFrame({ jsonrpc: "2.0", id: 7, result: { count: 2 } });

  decoder.push(frame.subarray(0, 12));
  decoder.push(frame.subarray(12));

  assert.deepEqual(messages, [
    { jsonrpc: "2.0", id: 7, result: { count: 2 } },
  ]);
});

test("FrameDecoder handles multiple frames in one chunk", () => {
  const messages: unknown[] = [];
  const decoder = new FrameDecoder((message) => messages.push(message));

  decoder.push(
    Buffer.concat([
      encodeFrame({ jsonrpc: "2.0", id: 1, result: "first" }),
      encodeFrame({ jsonrpc: "2.0", id: 2, result: "second" }),
    ]),
  );

  assert.deepEqual(messages, [
    { jsonrpc: "2.0", id: 1, result: "first" },
    { jsonrpc: "2.0", id: 2, result: "second" },
  ]);
});

test("FrameDecoder rejects oversized headers and bodies", () => {
  const decoder = new FrameDecoder(() => {});
  assert.throws(() => decoder.push(Buffer.alloc(8193, 65)), /header exceeds/);
  const bodyDecoder = new FrameDecoder(() => {});
  assert.throws(
    () => bodyDecoder.push(Buffer.from("Content-Length: 67108865\r\n\r\n")),
    /body exceeds/,
  );
});

test("FrameDecoder rejects noninteger and unsafe content lengths", () => {
  assert.throws(
    () => new FrameDecoder(() => {}).push(Buffer.from("Content-Length: nope\r\n\r\n")),
    /missing Content-Length/,
  );
  assert.throws(
    () => new FrameDecoder(() => {}).push(Buffer.from("Content-Length: 99999999999999999999\r\n\r\n")),
    /safe integer/,
  );
});
