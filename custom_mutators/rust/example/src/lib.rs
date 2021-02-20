#![allow(unused_variables)]

use custom_mutator::{export_mutator, CustomMutator};
use std::os::raw::c_uint;

struct ExampleMutator;

impl CustomMutator for ExampleMutator {
    type Error = ();

    fn init(seed: c_uint) -> Result<Self, ()> {
        Ok(Self)
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, ()> {
        buffer.reverse();
        Ok(Some(buffer))
    }
}

struct OwnBufferExampleMutator {
    own_buffer: Vec<u8>,
}

impl CustomMutator for OwnBufferExampleMutator {
    type Error = ();

    fn init(seed: c_uint) -> Result<Self, ()> {
        Ok(Self {
            own_buffer: Vec::new(),
        })
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, ()> {
        self.own_buffer.reverse();
        Ok(Some(self.own_buffer.as_slice()))
    }
}

export_mutator!(ExampleMutator);
