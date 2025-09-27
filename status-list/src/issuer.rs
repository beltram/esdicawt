mod cose;
mod lst_mut;
mod params;

pub use cose::{
    StatusListIssuer,
    model::{StatusListToken, StatusListTokenBuilder},
};
pub use lst_mut::LstMut;
pub use params::StatusListIssuerParams;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) fn elapsed_since_epoch() -> core::time::Duration {
    let val = js_sys::Date::now();
    std::time::Duration::from_millis(val as u64)
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) fn elapsed_since_epoch() -> core::time::Duration {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::SystemTime::UNIX_EPOCH).expect("System clock is before UNIX_EPOCH")
}
