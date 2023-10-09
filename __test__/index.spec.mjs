import test from 'ava'
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import * as fs from 'fs';
import { YaraCompiler } from '../index.js'

const TEST_RULE = "rule TestRule {\n    condition:\n        true\n}"
const __dirname = dirname(fileURLToPath(import.meta.url));

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

test('can load file based rules', (t) => {
  t.plan(1)
  t.notThrows(() => {
    const compiler = new YaraCompiler([{
      filename: join(__dirname, "./test.yara")
    }], []);
  });
})


test('can match file based rules', (t) => {
  t.plan(2)
  t.notThrows(() => {
    const compiler = new YaraCompiler([{
      filename: join(__dirname, "./test.yara")
    }], []);
    const scanner = compiler.newScanner();
    const result = scanner.scanString("Test");
    t.deepEqual(result, [
      {
        identifier: "TestRule",
        namespace: "default",
        metadatas: [
          {
            identifier: 'Author',
            value: 'MTRNord',
          },
          {
            identifier: 'Description',
            value: 'Test Rule',
          },
          {
            identifier: 'hash',
            value: '06fdc3d7d60da6b884fd69d7d1fd3c824ec417b2b7cdd40a7bb8c9fb72fb655b',
          },
          {
            identifier: 'Action',
            value: 'Notify',
          },
        ],
        tags: ["test_rule"],
        strings: [
          {
            identifier: '$test_string',
            matches: [
              {
                base: 0,
                data: [
                  84,
                  101,
                  115,
                  116
                ],
                length: 4,
                offset: 0,
              },
            ],
          },
        ]
      }
    ])
  });
})

if (process.platform !== "win32") {
  test('can match file based json rules', (t) => {
    const data = fs.readFileSync(join(__dirname, "./test.json"), 'utf8');
    t.plan(2)
    t.notThrows(() => {
      const compiler = new YaraCompiler([{
        filename: join(__dirname, "./json_test.yara")
      }, {
        filename: join(__dirname, "./test.yara")
      }], []);
      const scanner = compiler.newScanner();
      const result = scanner.scanString(data);
      t.deepEqual(result, [
        {
          identifier: "string_array_includes",
          namespace: "default",
          metadatas: [],
          tags: [],
          strings: []
        }, {
          identifier: "string_array_includes_nested",
          namespace: "default",
          metadatas: [],
          tags: [],
          strings: []
        }, {
          identifier: "integer_array_includes",
          namespace: "default",
          metadatas: [],
          tags: [],
          strings: []
        }, {
          identifier: "integer_array_includes_nested",
          namespace: "default",
          metadatas: [],
          tags: [],
          strings: []
        }, {
          identifier: "float_array_includes",
          namespace: "default",
          metadatas: [],
          tags: [],
          strings: []
        }, {
          identifier: "float_array_includes_nested",
          namespace: "default",
          metadatas: [],
          tags: [],
          strings: []
        }, {
          identifier: "dotted_key",
          namespace: "default",
          metadatas: [],
          tags: [],
          strings: []
        }, {
          identifier: "dotted_key_sub",
          namespace: "default",
          metadatas: [],
          tags: [],
          strings: []
        }, {
          identifier: "has_key_normal",
          namespace: "default",
          metadatas: [],
          tags: [],
          strings: []
        }
      ])
    });
  })
}