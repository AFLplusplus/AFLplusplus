#![allow(unused_variables)]

use custom_mutator::{export_mutator, fallible::FallibleCustomMutator, CustomMutator};
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

struct FallibleMutatorExample;

impl FallibleCustomMutator for FallibleMutatorExample {
    type Error = i32;

    fn init(seed: c_uint) -> Result<Self, i32> {
        Ok(Self)
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, i32> {
        Err(1)
    }

    fn handle_err(err: i32) {
        if std::env::var("DEBUG").is_ok() {
            eprintln!("Error in custom mutator: {}", err);
            // might panic in debug mode
        }
        // not panicing here -> continue execution
    }
}

export_mutator!(ExampleMutator);
