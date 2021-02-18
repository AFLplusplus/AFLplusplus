use custom_mutator::{export_mutator, CustomMutator, FuzzResult};

struct ExampleMutator;

impl CustomMutator for ExampleMutator {
    fn init(seed: std::os::raw::c_uint) -> Self
    where
        Self: Sized,
    {
        Self
    }

    fn fuzz(&mut self, buffer: &mut [u8], add_buff: Option<&[u8]>, max_size: usize) -> FuzzResult {
        buffer.reverse();
        FuzzResult::InPlace
    }
}

export_mutator!(ExampleMutator);
