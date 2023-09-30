#![deny(clippy::all)]

use napi::{anyhow::Context, bindgen_prelude::Buffer, Result};
use yara::{Compiler, Rules};

#[macro_use]
extern crate napi_derive;

#[napi(object)]
pub struct YaraRule {
  pub filename: Option<String>,
  pub string: Option<String>,
  pub namespace: Option<String>,
}

#[napi(object)]
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

#[napi]
pub struct YaraRuleResult {
  /// Name of the rule.
  pub identifier: String,
  /// Namespace of the rule.
  pub namespace: String,
  /// Metadatas of the rule.
  #[napi(ts_type = "Array<YaraRuleMetadata>")]
  pub metadatas: Vec<serde_json::Value>,
  /// Tags of the rule.
  pub tags: Vec<String>,
  /// Matcher strings of the rule.
  #[napi(ts_type = "Array<YaraString>")]
  pub strings: Vec<serde_json::Value>,
}

#[napi]
pub struct YaraRuleMetadata {
  pub identifier: String,
  pub integer_value: i64,
  pub string_value: String,
  pub bool_value: bool,
}

#[napi]
pub struct YaraString {
  /// Name of the string, with the '$'.
  pub identifier: String,
  /// Matches of the string for the scan.
  #[napi(ts_type = "Array<YaraMatch>")]
  pub matches: Vec<serde_json::Value>,
}

#[napi]
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

  #[napi]
  pub fn scan_buffer(&self, buffer: Buffer, timeout: i32) -> Result<Vec<YaraRuleResult>> {
    let buf: Vec<u8> = buffer.into();
    let results = self
      .rules
      .scan_mem(&buf, timeout)
      .context("Failed to scan buffer")?;

    let napi_results = results
      .iter()
      .map(|rule| YaraRuleResult {
        identifier: rule.identifier.to_string(),
        namespace: rule.namespace.to_string(),
        metadatas: rule
          .metadatas
          .iter()
          .map(|metadata| {
            serde_json::to_value(metadata).expect("Failed to serialize metadata in result")
          })
          .collect(),
        tags: rule.tags.iter().map(ToString::to_string).collect(),
        strings: rule
          .strings
          .iter()
          .map(|string| {
            serde_json::to_value(string).expect("Failed to serialize metadata in result")
          })
          .collect(),
      })
      .collect();

    Ok(napi_results)
  }
}
