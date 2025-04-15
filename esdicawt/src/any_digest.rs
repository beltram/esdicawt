use digest::{FixedOutput, FixedOutputReset, Output, OutputSizeUser, Reset, Update, consts::U32};

#[derive(Clone)]
pub struct AnyDigest;

impl OutputSizeUser for AnyDigest {
    type OutputSize = U32;
}

impl FixedOutput for AnyDigest {
    fn finalize_into(self, _: &mut Output<Self>) {
        todo!()
    }
}

impl Update for AnyDigest {
    fn update(&mut self, _: &[u8]) {
        todo!()
    }
}

impl Reset for AnyDigest {
    fn reset(&mut self) {
        todo!()
    }
}

impl FixedOutputReset for AnyDigest {
    fn finalize_into_reset(&mut self, _: &mut Output<Self>) {
        todo!()
    }
}

impl digest::Digest for AnyDigest {
    fn new() -> Self {
        todo!()
    }

    fn new_with_prefix(_: impl AsRef<[u8]>) -> Self {
        todo!()
    }

    fn update(&mut self, _: impl AsRef<[u8]>) {
        todo!()
    }

    fn chain_update(self, _: impl AsRef<[u8]>) -> Self {
        todo!()
    }

    fn finalize(self) -> Output<Self> {
        todo!()
    }

    fn finalize_into(self, _: &mut Output<Self>) {
        todo!()
    }

    fn finalize_reset(&mut self) -> Output<Self>
    where
        Self: FixedOutputReset,
    {
        todo!()
    }

    fn finalize_into_reset(&mut self, _: &mut Output<Self>)
    where
        Self: FixedOutputReset,
    {
        todo!()
    }

    fn reset(&mut self)
    where
        Self: Reset,
    {
        todo!()
    }

    fn output_size() -> usize {
        todo!()
    }

    fn digest(_: impl AsRef<[u8]>) -> Output<Self> {
        todo!()
    }
}
