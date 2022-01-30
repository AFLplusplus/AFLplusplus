#![cfg(unix)]
#![allow(unused_variables)]

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    cell::{RefCell, UnsafeCell},
    collections::HashMap,
    ffi::CStr,
};

use custom_mutator::{afl_state, export_mutator, CustomMutator};

use libafl::{
    bolts::{rands::StdRand, serdeany::SerdeAnyMap, tuples::Merge},
    corpus::{Corpus, Testcase},
    inputs::{BytesInput, HasBytesVec},
    mutators::{
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator, Tokens},
        Mutator,
    },
    state::{HasCorpus, HasMaxSize, HasMetadata, HasRand, State},
    Error,
};

const MAX_FILE: usize = 1 * 1024 * 1024;

static mut AFL: Option<&'static afl_state> = None;
static mut CURRENT_ENTRY: Option<usize> = None;

fn afl() -> &'static afl_state {
    unsafe { AFL.unwrap() }
}

#[derive(Default, Debug)]
pub struct AFLCorpus {
    entries: UnsafeCell<HashMap<usize, RefCell<Testcase<BytesInput>>>>,
}

impl Clone for AFLCorpus {
    fn clone(&self) -> Self {
        unsafe {
            Self {
                entries: UnsafeCell::new(self.entries.get().as_ref().unwrap().clone()),
            }
        }
    }
}

impl Serialize for AFLCorpus {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        unimplemented!();
    }
}

impl<'de> Deserialize<'de> for AFLCorpus {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        unimplemented!();
    }
}

impl Corpus<BytesInput> for AFLCorpus {
    #[inline]
    fn count(&self) -> usize {
        afl().queued_items as usize
    }

    #[inline]
    fn add(&mut self, testcase: Testcase<BytesInput>) -> Result<usize, Error> {
        unimplemented!();
    }

    #[inline]
    fn replace(&mut self, idx: usize, testcase: Testcase<BytesInput>) -> Result<(), Error> {
        unimplemented!();
    }

    #[inline]
    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<BytesInput>>, Error> {
        unimplemented!();
    }

    #[inline]
    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<BytesInput>>, Error> {
        unsafe {
            let entries = self.entries.get().as_mut().unwrap();
            entries.entry(idx).or_insert_with(|| {
                let queue_buf = std::slice::from_raw_parts_mut(afl().queue_buf, self.count());
                let entry = queue_buf[idx].as_mut().unwrap();
                let fname = CStr::from_ptr((entry.fname as *mut i8).as_ref().unwrap())
                    .to_str()
                    .unwrap()
                    .to_owned();
                let mut testcase = Testcase::with_filename(BytesInput::new(vec![]), fname);
                *testcase.input_mut() = None;
                RefCell::new(testcase)
            });
            Ok(&self.entries.get().as_ref().unwrap()[&idx])
        }
    }

    #[inline]
    fn current(&self) -> &Option<usize> {
        unsafe {
            CURRENT_ENTRY = Some(afl().current_entry as usize);
            &CURRENT_ENTRY
        }
    }

    #[inline]
    fn current_mut(&mut self) -> &mut Option<usize> {
        unimplemented!();
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AFLState {
    rand: StdRand,
    corpus: AFLCorpus,
    metadata: SerdeAnyMap,
    max_size: usize,
}

impl AFLState {
    pub fn new(seed: u32) -> Self {
        Self {
            rand: StdRand::with_seed(seed as u64),
            corpus: AFLCorpus::default(),
            metadata: SerdeAnyMap::new(),
            max_size: MAX_FILE,
        }
    }
}

impl State for AFLState {}

impl HasRand for AFLState {
    type Rand = StdRand;

    #[inline]
    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    #[inline]
    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}

impl HasCorpus<BytesInput> for AFLState {
    type Corpus = AFLCorpus;

    #[inline]
    fn corpus(&self) -> &Self::Corpus {
        &self.corpus
    }

    #[inline]
    fn corpus_mut(&mut self) -> &mut Self::Corpus {
        &mut self.corpus
    }
}

impl HasMetadata for AFLState {
    #[inline]
    fn metadata(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    #[inline]
    fn metadata_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl HasMaxSize for AFLState {
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }
}

struct LibAFLBaseCustomMutator {
    state: AFLState,
    input: BytesInput,
}

impl CustomMutator for LibAFLBaseCustomMutator {
    type Error = libafl::Error;

    fn init(afl: &'static afl_state, seed: u32) -> Result<Self, Self::Error> {
        unsafe {
            AFL = Some(afl);
            let mut state = AFLState::new(seed);
            let extras = std::slice::from_raw_parts(afl.extras, afl.extras_cnt as usize);
            let mut tokens = vec![];
            for extra in extras {
                let data = std::slice::from_raw_parts(extra.data, extra.len as usize);
                tokens.push(data.to_vec());
            }
            if !tokens.is_empty() {
                state.add_metadata(Tokens::new(tokens));
            }
            Ok(Self {
                state,
                input: BytesInput::new(vec![]),
            })
        }
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, Self::Error> {
        self.state.set_max_size(max_size);

        // TODO avoid copy
        self.input.bytes_mut().clear();
        self.input.bytes_mut().extend_from_slice(buffer);

        let mut mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
        mutator.mutate(&mut self.state, &mut self.input, 0)?;
        Ok(Some(self.input.bytes()))
    }
}

export_mutator!(LibAFLBaseCustomMutator);
