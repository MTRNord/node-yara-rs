import test from 'ava'

import { YaraCompiler } from '../index.js'

const TEST_RULE = "rule TestRule {\n    condition:\n        true\n}"

test('can construct YaraCompiler', (t) => {
  t.plan(1)
  t.notThrows(() => {
    const compiler = new YaraCompiler([], []);
  });
})

test('can load string rules', (t) => {
  t.plan(1)
  t.notThrows(() => {
    const compiler = new YaraCompiler([{
      string: TEST_RULE
    }], []);
  });
})


test('can match string rules', (t) => {
  t.plan(2)
  t.notThrows(() => {
    const compiler = new YaraCompiler([{
      string: TEST_RULE
    }], []);
    const scanner = compiler.newScanner();
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