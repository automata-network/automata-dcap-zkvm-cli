pub mod collaterals;
pub mod bonsai;
pub mod chain;
pub mod constants;
pub mod output;

// Shared methods go here...

pub fn remove_prefix_if_found(h: &str) -> &str {
    if h.starts_with("0x") {
        &h[2..]
    } else {
        &h
    }
}