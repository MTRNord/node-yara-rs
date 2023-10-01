#![deny(clippy::all)]

use napi::{anyhow::Context, bindgen_prelude::Buffer, Result};
use yara::{Compiler, MetadataValue, Rule as ExtYaraRule, Rules};

#[macro_use]
extern crate napi_derive;

#[napi(object)]
#[derive(Debug)]
pub struct YaraRule {
  pub filename: Option<String>,
  pub string: Option<String>,
  pub namespace: Option<String>,
}

#[napi(object)]
#[derive(Debug)]
pub struct YaraVariable {
  pub id: String,
  /// Limitation of napi-rs which doesnt support any
  pub integer_value: Option<i64>,
  /// Limitation of napi-rs which doesnt support any
  pub float_value: Option<f64>,
  /// Limitation of napi-rs which doesnt support any
  pub bool_value: Option<bool>,
  /// Limitation of napi-rs which doesnt support any
  pub string_value: Option<String>,
}

#[napi]
pub struct YaraScanner {
  rules: Rules,
}

#[napi(object)]
#[derive(Debug)]
pub struct YaraRuleResult {
  /// Name of the rule.
  pub identifier: String,
  /// Namespace of the rule.
  pub namespace: String,
  /// Metadatas of the rule.
  pub metadatas: Vec<YaraRuleMetadata>,
  /// Tags of the rule.
  pub tags: Vec<String>,
  /// Matcher strings of the rule.
  pub strings: Vec<YaraString>,
}

#[napi(object)]
#[derive(Debug, Default)]
pub struct YaraRuleMetadata {
  pub identifier: String,
  pub integer_value: Option<i64>,
  pub string_value: Option<String>,
  pub bool_value: Option<bool>,
}

#[napi(object)]
#[derive(Debug)]
pub struct YaraString {
  /// Name of the string, with the '$'.
  pub identifier: String,
  /// Matches of the string for the scan.
  pub matches: Vec<YaraMatch>,
}

#[napi(object)]
#[derive(Debug, Clone)]
pub struct YaraMatch {
  // base offset of the memory block in which the match occurred.
  pub base: i64,
  /// Offset of the match within the scanning area.
  pub offset: i64,
  /// Length of the file. Can be useful if the matcher string has not a fixed length.
  pub length: i64,
  /// Matched data.
  pub data: Vec<u8>,
}

#[napi]
impl YaraScanner {
  #[napi(constructor)]
  pub fn new(rules: Vec<YaraRule>, variables: Vec<YaraVariable>) -> napi::Result<Self> {
    let mut compiler = Compiler::new().context("Failed to create yara compiler")?;

    // Load variables
    for variable in variables {
      if let Some(string_value) = variable.string_value {
        compiler
          .define_variable(&variable.id, string_value.as_str())
          .context(format!("Failed to set variable with id: {}", variable.id))?;
      } else if let Some(bool_value) = variable.bool_value {
        compiler
          .define_variable(&variable.id, bool_value)
          .context(format!("Failed to set variable with id: {}", variable.id))?;
      } else if let Some(float_value) = variable.float_value {
        compiler
          .define_variable(&variable.id, float_value)
          .context(format!("Failed to set variable with id: {}", variable.id))?;
      } else if let Some(integer_value) = variable.integer_value {
        compiler
          .define_variable(&variable.id, integer_value)
          .context(format!("Failed to set variable with id: {}", variable.id))?;
      }
    }

    // Load rules
    for rule in rules {
      if let Some(namespace) = rule.namespace {
        if let Some(filepath) = rule.filename {
          compiler = compiler
            .add_rules_file_with_namespace(filepath.clone(), &namespace)
            .context(format!("Failed to load rule at {}", filepath))?;
        } else if let Some(string) = rule.string {
          compiler = compiler
            .add_rules_str_with_namespace(&string, &namespace)
            .context("Failed to load string rule")?;
        }
      } else if let Some(filepath) = rule.filename {
        compiler = compiler
          .add_rules_file(filepath.clone())
          .context(format!("Failed to load rule at {}", filepath))?;
      } else if let Some(string) = rule.string {
        compiler = compiler
          .add_rules_str(&string)
          .context("Failed to load string rule")?;
      }
    }

    let rules = compiler
      .compile_rules()
      .context("Failed to compile rules")?;

    Ok(YaraScanner { rules })
  }

  fn convert_yara_results(&self, rules: Vec<ExtYaraRule>) -> Vec<YaraRuleResult> {
    let results = rules
      .iter()
      .map(|rule| YaraRuleResult {
        identifier: rule.identifier.to_string(),
        namespace: rule.namespace.to_string(),
        metadatas: rule
          .metadatas
          .iter()
          .map(|metadata| match metadata.value {
            MetadataValue::Integer(int) => YaraRuleMetadata {
              identifier: metadata.identifier.to_string(),
              integer_value: Some(int),
              ..Default::default()
            },
            MetadataValue::String(string) => YaraRuleMetadata {
              identifier: metadata.identifier.to_string(),
              string_value: Some(string.to_string()),
              ..Default::default()
            },
            MetadataValue::Boolean(boolean) => YaraRuleMetadata {
              identifier: metadata.identifier.to_string(),
              bool_value: Some(boolean),
              ..Default::default()
            },
          })
          .collect(),
        tags: rule.tags.iter().map(ToString::to_string).collect(),
        strings: rule
          .strings
          .iter()
          .map(|string| YaraString {
            identifier: string.identifier.to_string(),
            matches: string
              .matches
              .iter()
              .map(|matches| YaraMatch {
                base: matches.base as i64,
                offset: matches.offset as i64,
                length: matches.length as i64,
                data: matches.data.clone(),
              })
              .collect(),
          })
          .collect(),
      })
      .collect();
    results
  }

  #[napi]
  pub fn scan_buffer(&self, buffer: Buffer) -> Result<Vec<YaraRuleResult>> {
    let mut scanner = self.rules.scanner().context("Failed to get scanner")?;
    let buf: Vec<u8> = buffer.into();
    let results = scanner.scan_mem(&buf).context("Failed to scan buffer")?;

    Ok(self.convert_yara_results(results))
  }

  #[napi]
  pub fn scan_string(&self, input: String) -> Result<Vec<YaraRuleResult>> {
    let mut scanner = self.rules.scanner().context("Failed to get scanner")?;
    let buf: &[u8] = input.as_bytes();
    let results = scanner.scan_mem(buf).context("Failed to scan buffer")?;

    Ok(self.convert_yara_results(results))
  }
}
