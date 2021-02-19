use custom_mutator::{export_mutator, CustomMutator};
use std::os::raw::c_uint;

struct ExampleMutator;

impl CustomMutator for ExampleMutator {
    fn init(seed: c_uint) -> Self {
        Self
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Option<&'b [u8]> {
        buffer.reverse();
        Some(buffer)
    }
}

struct OwnBufferExampleMutator {
    own_buffer: Vec<u8>,
}

impl CustomMutator for OwnBufferExampleMutator {
    fn init(seed: c_uint) -> Self {
        Self {
            own_buffer: Vec::new(),
        }
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Option<&'b [u8]> {
        self.own_buffer.reverse();
        Some(self.own_buffer.as_slice())
    }
}

export_mutator!(ExampleMutator);
