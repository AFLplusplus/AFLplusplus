#![cfg(unix)]

use std::{
    cell::{RefCell, UnsafeCell},
    collections::HashMap,
    ffi::CStr,
};

use custom_mutator::{CustomMutator, afl_state, export_mutator};
use libafl::{
    Error, HasMetadata,
    corpus::{Corpus, CorpusId, Testcase},
    inputs::BytesInput,
    mutators::{
        HavocScheduledMutator, Mutator, Tokens, havoc_mutations::havoc_mutations, tokens_mutations,
    },
    state::{HasMaxSize, StdState},
};
use libafl_bolts::{rands::StdRand, tuples::Merge};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

static mut AFL: Option<&'static afl_state> = None;
static mut CURRENT_ENTRY: Option<CorpusId> = None;

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
    fn add(&mut self, _testcase: Testcase<BytesInput>) -> Result<CorpusId, Error> {
        unimplemented!();
    }

    #[inline]
    fn replace(
        &mut self,
        _idx: CorpusId,
        _testcase: Testcase<BytesInput>,
    ) -> Result<Testcase<BytesInput>, Error> {
        unimplemented!();
    }

    #[inline]
    fn remove(&mut self, _idx: CorpusId) -> Result<Testcase<BytesInput>, Error> {
        unimplemented!();
    }

    #[inline]
    fn get(&self, idx: CorpusId) -> Result<&RefCell<Testcase<BytesInput>>, Error> {
        let idx_usize: usize = idx.into();
        unsafe {
            let entries = self.entries.get().as_mut().unwrap();
            entries.entry(idx_usize).or_insert_with(|| {
                let queue_buf = std::slice::from_raw_parts_mut(afl().queue_buf, self.count());
                let entry = queue_buf[idx_usize].as_mut().unwrap();
                let fname = CStr::from_ptr((entry.fname.cast::<i8>()).as_ref().unwrap())
                    .to_str()
                    .unwrap()
                    .to_owned();
                let mut testcase = Testcase::with_filename(BytesInput::new(vec![]), fname);
                *testcase.input_mut() = None;
                RefCell::new(testcase)
            });
            Ok(&self.entries.get().as_ref().unwrap()[&idx_usize])
        }
    }

    #[inline]
    #[allow(static_mut_refs)]
    fn current(&self) -> &Option<CorpusId> {
        unsafe {
            CURRENT_ENTRY = Some(CorpusId::from(afl().current_entry as usize));
            &CURRENT_ENTRY
        }
    }

    #[inline]
    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        unimplemented!();
    }

    fn next(&self, _idx: CorpusId) -> Option<CorpusId> {
        todo!()
    }

    fn prev(&self, _idx: CorpusId) -> Option<CorpusId> {
        todo!()
    }

    fn first(&self) -> Option<CorpusId> {
        todo!()
    }

    fn last(&self) -> Option<CorpusId> {
        todo!()
    }

    fn peek_free_id(&self) -> CorpusId {
        todo!()
    }

    fn get_from_all(&self, _id: CorpusId) -> Result<&RefCell<Testcase<BytesInput>>, Error> {
        todo!()
    }

    fn count_all(&self) -> usize {
        self.count()
    }

    fn count_disabled(&self) -> usize {
        0
    }

    fn add_disabled(&mut self, _testcase: Testcase<BytesInput>) -> Result<CorpusId, Error> {
        todo!()
    }

    fn nth_from_all(&self, _nth: usize) -> CorpusId {
        todo!()
    }

    fn load_input_into(&self, _testcase: &mut Testcase<BytesInput>) -> Result<(), Error> {
        todo!()
    }

    fn store_input_from(&self, _testcase: &Testcase<BytesInput>) -> Result<(), Error> {
        todo!()
    }
}

struct LibAFLBaseCustomMutator {
    state: StdState<AFLCorpus, BytesInput, StdRand, AFLCorpus>,
    input: BytesInput,
}

impl CustomMutator for LibAFLBaseCustomMutator {
    type Error = libafl::Error;

    fn init(afl: &'static afl_state, seed: u32) -> Result<Self, Self::Error> {
        unsafe {
            AFL = Some(afl);
            let rand = StdRand::with_seed(u64::from(seed));
            let corpus = AFLCorpus::default();
            let solutions = AFLCorpus::default();
            let mut feedback = ();
            let mut objective = ();
            let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)?;

            let extras = std::slice::from_raw_parts(afl.extras, afl.extras_cnt as usize);
            let mut tokens = vec![];
            for extra in extras {
                let data = std::slice::from_raw_parts(extra.data, extra.len as usize);
                tokens.push(data.to_vec());
            }
            if !tokens.is_empty() {
                state.add_metadata(Tokens::from(tokens));
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
        _add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, Self::Error> {
        self.state.set_max_size(max_size);

        // TODO avoid copy
        self.input = BytesInput::new(buffer.to_vec());

        let mut mutator = HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
        mutator.mutate(&mut self.state, &mut self.input)?;
        Ok(Some(self.input.as_ref()))
    }
}

export_mutator!(LibAFLBaseCustomMutator);
