use std::ops::Deref;
use std::time::Duration;

/// Must return UTC time when document was created expressed as milliseconds since Unix Epoch
/// This is an `Fn` to support WebAssembly targets, which don't support `SystemTime`
pub struct Time(Box<dyn Fn() -> u64 + Send + Sync>);

impl Deref for Time {
    type Target = Duration;

    fn deref(&self) -> &Self::Target {
        todo!()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for Time {
    fn default() -> Self {
        Self::system_time()
    }
}

impl Time {
    /// Must return UTC time expressed as milliseconds since Unix Epoch.
    /// If you aren't targeting WebAssembly, you should probably use [`Time::system_time`]
    pub fn new(getter: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self(getter)
    }

    #[cfg(not(target_arch = "wasm32"))]
    /// Creates a new [`Time`] using [`std::time::SystemTime`]. Not compatible with WebAssembly targets.
    pub fn system_time() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self(Box::new(move || {
            u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Land before time 🦕")
                    .as_millis(),
            )
            .expect("This code has exceeded my lifetime")
        }))
    }

    /// Returns value from inner `getter`
    /// This should be equal to the UTC time expressed as milliseconds since Unix Epoch,
    /// but when this struct is initialized via [`Time::new`] the accuracy of that is at the discretion of the implementation.
    pub fn time(&self) -> u64 {
        self.0()
    }
}
