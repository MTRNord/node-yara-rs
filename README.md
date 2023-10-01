# Node-yara-rs

Node-yara-rs is a node module binding for the [yara-rs](https://github.com/Hugal31/yara-rust/) library which in turn does bind to [libyara](https://github.com/VirusTotal/yara).

## Installation

You can install this with npm or yarn as usual:

```bash
npm install --save @node_yara_rs/node-yara-rs
```

## Usage

```typescript
// Import the package
import { YaraCompiler } from '@node_yara_rs/node-yara-rs'

// Load your rules as a string or filepaths

// Create a new compiler which loads a rule (checkout the typings for more details)
const compiler = new YaraCompiler([{
    string: TEST_RULE
}], []);

// Get a scanner which is used to then scan data
const scanner = compiler.newScanner();

// Scan some string
const result = scanner.scanString("test");
```

Note that most functions here are able to throw if anything fails. Handle these as needed.

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[Apache-2.0](https://choosealicense.com/licenses/apache-2.0/)
