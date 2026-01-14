use digest::{FixedOutput, FixedOutputReset, Output, OutputSizeUser, Reset, Update, consts::U32};

#[derive(Clone)]
pub struct AnyDigest;

impl OutputSizeUser for AnyDigest {
    type OutputSize = U32;
}

impl FixedOutput for AnyDigest {
    fn finalize_into(self, _: &mut Output<Self>) {}
}

impl Update for AnyDigest {
    fn update(&mut self, _: &[u8]) {}
}

impl Reset for AnyDigest {
    fn reset(&mut self) {}
}

impl FixedOutputReset for AnyDigest {
    fn finalize_into_reset(&mut self, _: &mut Output<Self>) {}
}

impl digest::Digest for AnyDigest {
    fn new() -> Self {
        Self
    }

    fn new_with_prefix(_: impl AsRef<[u8]>) -> Self {
        Self
    }

    fn update(&mut self, _: impl AsRef<[u8]>) {}

    fn chain_update(self, _: impl AsRef<[u8]>) -> Self {
        self
    }

    fn finalize(self) -> Output<Self> {
        Default::default()
    }

    fn finalize_into(self, _: &mut Output<Self>) {}

    fn finalize_reset(&mut self) -> Output<Self>
    where
        Self: FixedOutputReset,
    {
        Default::default()
    }

    fn finalize_into_reset(&mut self, _: &mut Output<Self>)
    where
        Self: FixedOutputReset,
    {
    }

    fn reset(&mut self)
    where
        Self: Reset,
    {
    }

    fn output_size() -> usize {
        0
    }

    fn digest(_: impl AsRef<[u8]>) -> Output<Self> {
        Default::default()
    }
}
