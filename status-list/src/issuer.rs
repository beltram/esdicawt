pub(crate) mod cose;
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
    let js_date = js_sys::Date::new_0();
    let timestamp_millis = js_date.get_time() as u64;
    std::time::Duration::from_millis(timestamp_millis)
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) fn elapsed_since_epoch() -> core::time::Duration {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::SystemTime::UNIX_EPOCH).expect("System clock is before UNIX_EPOCH")
}
