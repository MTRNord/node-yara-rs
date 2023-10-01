#![deny(clippy::all)]

use napi::{
  anyhow::{anyhow, Context},
  bindgen_prelude::{Buffer, Reference, SharedReference},
  Env, Result,
};
use yara::{Compiler, MetadataValue, Rule as ExtYaraRule, Rules, Scanner};

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

/// An interface to use yara with node in a stable manner using Rust
/// @public
#[napi]
pub struct YaraCompiler {
  rules: Rules,
}

/// An interface to use yara with node in a stable manner using Rust
/// @public
#[napi]
pub struct YaraScanner {
  scanner: SharedReference<YaraCompiler, Scanner<'static>>,
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
impl YaraCompiler {
  /// Constructs a new Yara instance and compiles the provided rules and variables.
  ///
  /// @param rules - The rules which shall be compiled.
  /// @param variables - The variables you want to pass to the rules.
  /// @throws This can throw if there is an unexpected error.
  ///
  /// @returns A new instance of a YaraScanner which can be used to scan data
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

    Ok(YaraCompiler { rules })
  }

  /// Creates a new yara scanner for the rules defined earlier.
  /// This can be called multiple times
  ///
  /// @returns A {@link YaraScanner} instance
  #[napi]
  pub fn new_scanner(&self, reference: Reference<YaraCompiler>, env: Env) -> Result<YaraScanner> {
    YaraScanner::new(reference, env)
  }
}

#[napi]
impl YaraScanner {
  pub fn new(reference: Reference<YaraCompiler>, env: Env) -> Result<Self> {
    let scanner = reference.share_with(env, |compiler| {
      Ok(compiler.rules.scanner().context("Failed to get scanner")?)
    })?;
    Ok(YaraScanner { scanner })
  }

  /// Converts the yara-rs types to types which we can return to napi-rs.
  /// Ideally we dont need this but sadly for now this is required.
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

  /// Scan a buffer of data with yara
  ///
  /// @param buffer - The data which shall be scanned by yara.
  /// @throws This can throw if there is an unexpected error.
  ///
  /// @returns The results of yara scan_mem.
  #[napi]
  pub fn scan_buffer(&mut self, buffer: Buffer) -> Result<Vec<YaraRuleResult>> {
    let buf: Vec<u8> = buffer.into();
    let results = self
      .scanner
      .scan_mem(&buf)
      .context("Failed to scan buffer")?;

    Ok(self.convert_yara_results(results))
  }

  /// Scan a string of data with yara
  ///
  /// @param input - The data which shall be scanned by yara.
  /// @throws This can throw if there is an unexpected error.
  ///
  /// @returns The results of yara scan_mem.
  #[napi]
  pub fn scan_string(&mut self, input: String) -> Result<Vec<YaraRuleResult>> {
    let buf: &[u8] = input.as_bytes();
    let results = self
      .scanner
      .scan_mem(buf)
      .context("Failed to scan string")?;

    Ok(self.convert_yara_results(results))
  }

  /// Scan a file with yara
  ///
  /// @param filepath - The path to the file yara shall scan
  /// @throws This can throw if there is an unexpected error.
  ///
  /// @returns The results of yara scan_mem.
  #[napi]
  pub fn scan_file(&mut self, filepath: String) -> Result<Vec<YaraRuleResult>> {
    let results = self
      .scanner
      .scan_file(filepath)
      .context("Failed to scan file")?;

    Ok(self.convert_yara_results(results))
  }

  /// Scan a process with yara
  ///
  /// @param pid - The process id of the process that shall be scanned.
  /// @throws This can throw if there is an unexpected error.
  ///
  /// @returns The results of yara scan_mem.
  #[napi]
  pub fn scan_process(&mut self, pid: u32) -> Result<Vec<YaraRuleResult>> {
    let results = self
      .scanner
      .scan_process(pid)
      .context("Failed to scan file")?;

    Ok(self.convert_yara_results(results))
  }

  #[napi]
  pub fn define_variable(
    &mut self,
    identifier: String,
    string_value: Option<String>,
    integer_value: Option<i64>,
    float_value: Option<f64>,
    bool_value: Option<bool>,
  ) -> Result<()> {
    if let Some(string_value) = string_value {
      Ok(
        self
          .scanner
          .define_variable(&identifier, string_value.as_str())
          .context(format!("Failed to define string variable: {identifier}"))?,
      )
    } else if let Some(bool_value) = bool_value {
      Ok(
        self
          .scanner
          .define_variable(&identifier, bool_value)
          .context(format!("Failed to define bool variable: {identifier}"))?,
      )
    } else if let Some(float_value) = float_value {
      Ok(
        self
          .scanner
          .define_variable(&identifier, float_value)
          .context(format!("Failed to define float variable: {identifier}"))?,
      )
    } else if let Some(integer_value) = integer_value {
      Ok(
        self
          .scanner
          .define_variable(&identifier, integer_value)
          .context(format!("Failed to define integer variable: {identifier}"))?,
      )
    } else {
      Err(anyhow!("You must at least define one of the value types!").into())
    }
  }
}
