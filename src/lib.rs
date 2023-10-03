#![deny(clippy::all)]

use napi::{
  anyhow::Context,
  bindgen_prelude::{Buffer, Either3, Either4, Reference, SharedReference},
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
  pub value: Either4<i64, f64, bool, String>,
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
#[derive(Debug)]
pub struct YaraRuleMetadata {
  pub identifier: String,
  pub value: Either3<i64, String, bool>,
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
      match variable.value {
        Either4::A(integer_value) => {
          compiler
            .define_variable(&variable.id, integer_value)
            .context(format!("Failed to set variable with id: {}", variable.id))?;
        }
        Either4::B(float_value) => {
          compiler
            .define_variable(&variable.id, float_value)
            .context(format!("Failed to set variable with id: {}", variable.id))?;
        }
        Either4::C(bool_value) => {
          compiler
            .define_variable(&variable.id, bool_value)
            .context(format!("Failed to set variable with id: {}", variable.id))?;
        }
        Either4::D(string_value) => {
          compiler
            .define_variable(&variable.id, string_value.as_str())
            .context(format!("Failed to set variable with id: {}", variable.id))?;
        }
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
              value: Either3::A(int),
            },
            MetadataValue::String(string) => YaraRuleMetadata {
              identifier: metadata.identifier.to_string(),
              value: Either3::B(string.to_string()),
            },
            MetadataValue::Boolean(boolean) => YaraRuleMetadata {
              identifier: metadata.identifier.to_string(),
              value: Either3::C(boolean),
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
    value: Either4<String, i64, f64, bool>,
  ) -> Result<()> {
    match value {
      Either4::A(string_value) => Ok(
        self
          .scanner
          .define_variable(&identifier, string_value.as_str())
          .context(format!("Failed to define string variable: {identifier}"))?,
      ),
      Either4::B(bool_value) => Ok(
        self
          .scanner
          .define_variable(&identifier, bool_value)
          .context(format!("Failed to define bool variable: {identifier}"))?,
      ),
      Either4::C(float_value) => Ok(
        self
          .scanner
          .define_variable(&identifier, float_value)
          .context(format!("Failed to define float variable: {identifier}"))?,
      ),
      Either4::D(integer_value) => Ok(
        self
          .scanner
          .define_variable(&identifier, integer_value)
          .context(format!("Failed to define integer variable: {identifier}"))?,
      ),
    }
  }
}
