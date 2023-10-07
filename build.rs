use std::path::PathBuf;

extern crate napi_build;

fn main() {
  println!("cargo:rerun-if-changed=build");
  println!("cargo:rerun-if-changed=deps");

  // Workaround weird jansson linking

  if !cfg!(target_os = "windows") {
    let base = env!("CARGO_MANIFEST_DIR");
    let mut include_path = PathBuf::from(base);
    include_path.push("build/jansson/lib");

    println!("cargo:rustc-link-search=native={}", include_path.display());
    println!("cargo:rustc-link-lib=static=jansson");
  }
  napi_build::setup();
}
