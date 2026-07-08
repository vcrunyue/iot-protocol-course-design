import assert from "node:assert/strict";
import {
  caesarTransform,
  checksum,
  decryptBytes,
  encryptBytes,
  frameToHex,
  parseFrame,
  simulateTransmission,
} from "./app.js";

const bytes = new TextEncoder().encode("Hello");

const xorEncrypted = encryptBytes(bytes, "xor", 18);
assert.notDeepEqual(Array.from(xorEncrypted), Array.from(bytes));
assert.deepEqual(Array.from(decryptBytes(xorEncrypted, "xor", 18)), Array.from(bytes));

const caesarEncrypted = caesarTransform(bytes, 3);
assert.notDeepEqual(Array.from(caesarEncrypted), Array.from(bytes));
assert.deepEqual(Array.from(caesarTransform(caesarEncrypted, -3)), Array.from(bytes));

assert.equal(checksum(Uint8Array.from([0x10, 0x20, 0x30])), 0x00);
assert.equal(frameToHex(Uint8Array.from([0x0a, 0x1b, 0xff])), "0A 1B FF");

const frame = simulateTransmission(xorEncrypted, 0).sentFrame;
const parsed = parseFrame(frame);
assert.equal(parsed.ok, true);
assert.equal(parsed.length, xorEncrypted.length);
assert.deepEqual(Array.from(parsed.payload), Array.from(xorEncrypted));
assert.equal(parsed.checksumPassed, true);

const damaged = simulateTransmission(xorEncrypted, 100);
const damagedParsed = parseFrame(damaged.receivedFrame);
assert.equal(damaged.changed, true);
assert.equal(damagedParsed.ok && damagedParsed.checksumPassed, false);

console.log("Web protocol tests passed");
