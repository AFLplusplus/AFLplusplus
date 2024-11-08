#![cfg(unix)]

use custom_mutator::{export_mutator, CustomMutator};
use lain::{
    mutator::Mutator,
    prelude::*,
    rand::{rngs::StdRng, SeedableRng},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Mutatable, NewFuzzed, BinarySerialize)]
struct MyStruct {
    tag: u8,
    #[lain(ignore)]
    length: u32,
    #[lain(min = 0, max = 10)]
    data: Vec<u8>,
}

struct LainMutator {
    mutator: Mutator<StdRng>,
    buffer: Vec<u8>,
    post_buffer: Vec<u8>,
}

impl CustomMutator for LainMutator {
    type Error = ();

    fn init(seed: u32) -> Result<Self, ()> {
        Ok(Self {
            mutator: Mutator::new(StdRng::seed_from_u64(seed as u64)),
            buffer: Vec::new(),
            post_buffer: Vec::new(),
        })
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        _buffer: &'b mut [u8],
        _add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, ()> {
        // we just sample an instance of MyStruct, ignoring the current input
        let instance = MyStruct::new_fuzzed(&mut self.mutator, None);
        let serialized = bincode::serialize(&instance).unwrap();
        let size = serialized.len();
        if size > max_size {
            return Err(());
        }
        self.buffer.clear();
        self.buffer.reserve(size);
        self.buffer.extend_from_slice(&serialized);
        Ok(Some(self.buffer.as_slice()))
    }

    fn post_process<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
    ) -> Result<Option<&'b [u8]>, Self::Error> {
        let mut instance = bincode::deserialize::<MyStruct>(&buffer).unwrap();
        instance.length = instance.data.len() as u32;
        let size = instance.serialized_size();
        self.post_buffer.clear();
        self.post_buffer.reserve(size);
        instance.binary_serialize::<_, BigEndian>(&mut self.post_buffer);
        Ok(Some(&self.post_buffer))
    }
}

export_mutator!(LainMutator);
