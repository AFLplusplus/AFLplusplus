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

    fn handle_error(err: Self::Error) {
        if std::env::var("AFL_CUSTOM_MUTATOR_DEBUG")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
            eprintln!("Error in custom mutator: {:?}", err)
        }
    }

    fn fuzz_count(&mut self, buffer: &[u8]) -> Result<u32, Self::Error> {
        Ok(1)
    }

    fn queue_new_entry(
        &mut self,
        filename_new_queue: &std::ffi::OsStr,
        filename_orig_queue: Option<&std::ffi::OsStr>,
    ) -> Result<(), Self::Error> {
        eprintln!(
            "filename_new_queue {:#?}, filename_orig_queue {:#?}",
            filename_new_queue, filename_orig_queue
        );
        Ok(())
    }

    fn queue_get(&mut self, filename: &std::ffi::OsStr) -> Result<bool, Self::Error> {
        eprintln!("filename {:#?}", filename);
        Ok(true)
    }

    fn describe(&mut self, max_description: usize) -> Result<Option<&str>, Self::Error> {
        Ok(Some("MyMutator"))
    }

    fn introspection(&mut self) -> Result<Option<&str>, Self::Error> {
        Ok(None)
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
