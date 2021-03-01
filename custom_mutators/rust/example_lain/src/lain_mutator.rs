#![cfg(unix)]

use custom_mutator::{export_mutator, CustomMutator};
use lain::{
    mutator::Mutator,
    prelude::*,
    rand::{rngs::StdRng, SeedableRng},
};

#[derive(Debug, Mutatable, NewFuzzed, BinarySerialize)]
struct MyStruct {
    field_1: u8,

    #[lain(bits = 3)]
    field_2: u8,

    #[lain(bits = 5)]
    field_3: u8,

    #[lain(min = 5, max = 10000)]
    field_4: u32,

    #[lain(ignore)]
    ignored_field: u64,
}

struct LainMutator {
    mutator: Mutator<StdRng>,
    buffer: Vec<u8>,
}

impl CustomMutator for LainMutator {
    type Error = ();

    fn init(seed: u32) -> Result<Self, ()> {
        Ok(Self {
            mutator: Mutator::new(StdRng::seed_from_u64(seed as u64)),
            buffer: Vec::new(),
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
        let size = instance.serialized_size();
        if size > max_size {
            return Err(());
        }
        self.buffer.clear();
        self.buffer.reserve(size);
        instance.binary_serialize::<_, BigEndian>(&mut self.buffer);
        Ok(Some(self.buffer.as_slice()))
    }
}

export_mutator!(LainMutator);
