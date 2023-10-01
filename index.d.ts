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
  /** Limitation of napi-rs which doesnt support any */
  integerValue?: number
  /** Limitation of napi-rs which doesnt support any */
  floatValue?: number
  /** Limitation of napi-rs which doesnt support any */
  boolValue?: boolean
  /** Limitation of napi-rs which doesnt support any */
  stringValue?: string
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
  integerValue?: number
  stringValue?: string
  boolValue?: boolean
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
}
export class YaraScanner {
  constructor(rules: Array<YaraRule>, variables: Array<YaraVariable>)
  scanBuffer(buffer: Buffer): Array<YaraRuleResult>
  scanString(input: string): Array<YaraRuleResult>
}
