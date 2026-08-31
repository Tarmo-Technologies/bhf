// SPDX-License-Identifier: Apache-2.0
// M23 Phase 2: interprocedural taint for Rust. A source-like parameter reaching
// a command sink (std::process::Command) is BHF-304 (proven flow). These use
// Command::new(arg) WITHOUT a shell literal so only the taint engine fires (no
// BHF-404 overlap), isolating BHF-304.
fn run(user_input: &str) {
    std::process::Command::new(user_input); // EXPECT BHF-304
}

fn dispatch(user_query: String) {
    forward(user_query);
}

fn forward(a: String) {
    std::process::Command::new(a); // EXPECT BHF-304
}

fn clean(user_path: &str) {
    let v = sanitize(user_path);
    std::process::Command::new(v);
}

fn log_user(user_input: &str) {
    log::warn!("{}", user_input); // EXPECT BHF-544
    log::info!("fixed");
}
