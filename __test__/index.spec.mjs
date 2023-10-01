import test from 'ava'

import { YaraScanner } from '../index.js'

const TEST_RULE = "rule TestRule {\n    condition:\n        true\n}"

test('can construct YaraScanner', (t) => {
  t.plan(1)
  t.notThrows(() => {
    const scanner = new YaraScanner([], []);
  });
})

test('can load string rules', (t) => {
  t.plan(1)
  t.notThrows(() => {
    const scanner = new YaraScanner([{
      string: TEST_RULE
    }], []);
  });
})


test('can match string rules', (t) => {
  t.plan(2)
  t.notThrows(() => {
    const scanner = new YaraScanner([{
      string: TEST_RULE
    }], []);
    const result = scanner.scanString("");
    t.deepEqual(result, [
      {
        identifier: "TestRule",
        namespace: "default",
        metadatas: [],
        tags: [],
        strings: []
      }
    ])
  });
})