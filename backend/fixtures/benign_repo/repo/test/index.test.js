const test = require("node:test");
const assert = require("node:assert");
const { price } = require("../index.js");

test("multiplies cents by quantity", () => assert.strictEqual(price(250, 3), 750));
test("rejects a zero quantity", () => assert.throws(() => price(250, 0)));
