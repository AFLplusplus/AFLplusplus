#![cfg(unix)]
#![allow(unused_variables)]

use custom_mutator::{export_mutator, CustomMutator};

struct ExampleMutator;

impl CustomMutator for ExampleMutator {
    type Error = ();

    fn init(seed: u32) -> Result<Self, Self::Error> {
        Ok(Self)
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, Self::Error> {
        buffer.reverse();
        Ok(Some(buffer))
    }
}

struct OwnBufferExampleMutator {
    own_buffer: Vec<u8>,
}

impl CustomMutator for OwnBufferExampleMutator {
    type Error = ();

    fn init(seed: u32) -> Result<Self, Self::Error> {
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
