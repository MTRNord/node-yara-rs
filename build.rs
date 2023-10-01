extern crate napi_build;

fn main() {
  println!("cargo:rerun-if-changed=build");
  println!("cargo:rerun-if-changed=deps");
  napi_build::setup();
}
