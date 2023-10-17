/* tslint:disable */
/* eslint-disable */

/* auto-generated by NAPI-RS */

export interface YaraRule {
  filename?: string
  string?: string
  namespace?: string
}
export interface YaraVariable {
  id: string
  value: number | number | boolean | string
}
export interface YaraRuleResult {
  /** Name of the rule. */
  identifier: string
  /** Namespace of the rule. */
  namespace: string
  /** Metadatas of the rule. */
  metadatas: Array<YaraRuleMetadata>
  /** Tags of the rule. */
  tags: Array<string>
  /** Matcher strings of the rule. */
  strings: Array<YaraString>
}
export interface YaraRuleMetadata {
  identifier: string
  value: number | string | boolean
}
export interface YaraString {
  /** Name of the string, with the '$'. */
  identifier: string
  /** Matches of the string for the scan. */
  matches: Array<YaraMatch>
}
export interface YaraMatch {
  base: number
  /** Offset of the match within the scanning area. */
  offset: number
  /** Length of the file. Can be useful if the matcher string has not a fixed length. */
  length: number
  /** Matched data. */
  data: Array<number>
  /** If utf-8 then we decode it here */
  stringData?: string
}
/**
 * An interface to use yara with node in a stable manner using Rust
 * @public
 */
export class YaraCompiler {
  /**
   * Constructs a new Yara instance and compiles the provided rules and variables.
   *
   * @param rules - The rules which shall be compiled.
   * @param variables - The variables you want to pass to the rules.
   * @throws This can throw if there is an unexpected error.
   *
   * @returns A new instance of a YaraScanner which can be used to scan data
   */
  constructor(rules: Array<YaraRule>, variables: Array<YaraVariable>)
  /**
   * Creates a new yara scanner for the rules defined earlier.
   * This can be called multiple times
   *
   * @returns A {@link YaraScanner} instance
   */
  newScanner(): YaraScanner
}
/**
 * An interface to use yara with node in a stable manner using Rust
 * @public
 */
export class YaraScanner {
  /**
   * Scan a buffer of data with yara
   *
   * @param buffer - The data which shall be scanned by yara.
   * @throws This can throw if there is an unexpected error.
   *
   * @returns The results of yara scan_mem.
   */
  scanBuffer(buffer: Buffer): Array<YaraRuleResult>
  /**
   * Scan a string of data with yara
   *
   * @param input - The data which shall be scanned by yara.
   * @throws This can throw if there is an unexpected error.
   *
   * @returns The results of yara scan_mem.
   */
  scanString(input: string): Array<YaraRuleResult>
  /**
   * Scan a file with yara
   *
   * @param filepath - The path to the file yara shall scan
   * @throws This can throw if there is an unexpected error.
   *
   * @returns The results of yara scan_mem.
   */
  scanFile(filepath: string): Array<YaraRuleResult>
  /**
   * Scan a process with yara
   *
   * @param pid - The process id of the process that shall be scanned.
   * @throws This can throw if there is an unexpected error.
   *
   * @returns The results of yara scan_mem.
   */
  scanProcess(pid: number): Array<YaraRuleResult>
  defineVariable(identifier: string, value: string | number | number | boolean): void
}
