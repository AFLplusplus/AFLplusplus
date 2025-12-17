#![cfg(unix)]

use std::{
    cell::{RefCell, UnsafeCell},
    ffi::CStr,
    marker::PhantomData,
};

use custom_mutator::{CustomMutator, afl_state};
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

pub trait AflDeserializer<I> {
    fn deserialize(bytes: &[u8]) -> Result<I, Error>;
}

#[derive(Default)]
pub struct BytesInputDeserializer;
impl AflDeserializer<BytesInput> for BytesInputDeserializer {
    fn deserialize(bytes: &[u8]) -> Result<BytesInput, Error> {
        Ok(BytesInput::new(bytes.to_vec()))
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct AflStructDeserializer;

impl<I> AflDeserializer<I> for AflStructDeserializer
where
    I: serde::de::DeserializeOwned,
{
    fn deserialize(bytes: &[u8]) -> Result<I, Error> {
        if let Ok(i) = postcard::from_bytes::<I>(bytes) {
            Ok(i)
        } else {
            #[cfg(feature = "json")]
            {
                serde_json::from_slice::<I>(bytes)
                    .map_err(|e| Error::unknown(format!("Failed to deserialize input: {}", e)))
            }
            #[cfg(not(feature = "json"))]
            {
                Err(Error::unknown(
                    "Failed to deserialize input (Postcard failed, JSON disabled)",
                ))
            }
        }
    }
}

use std::num::NonZeroUsize;

use lru::LruCache;

#[derive(Debug)]
pub struct AflCorpus<I = BytesInput, D = BytesInputDeserializer> {
    entries: UnsafeCell<LruCache<usize, Box<RefCell<Testcase<I>>>>>,
    phantom: PhantomData<D>,
}

impl<I, D> Default for AflCorpus<I, D> {
    fn default() -> Self {
        Self {
            entries: UnsafeCell::new(LruCache::new(NonZeroUsize::new(4096).unwrap())),
            phantom: PhantomData,
        }
    }
}

impl<I, D> Clone for AflCorpus<I, D>
where
    I: Clone,
{
    fn clone(&self) -> Self {
        // Create a new empty cache.
        unsafe {
            let cap = self.entries.get().as_ref().unwrap().cap();
            Self {
                entries: UnsafeCell::new(LruCache::new(cap)),
                phantom: PhantomData,
            }
        }
    }
}

impl<I, D> Serialize for AflCorpus<I, D> {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        unimplemented!();
    }
}

impl<'de, I, D> Deserialize<'de> for AflCorpus<I, D> {
    fn deserialize<D_>(_deserializer: D_) -> Result<Self, D_::Error>
    where
        D_: Deserializer<'de>,
    {
        unimplemented!();
    }
}

impl<I, D> Corpus<I> for AflCorpus<I, D>
where
    I: libafl::inputs::Input + Clone,
    D: AflDeserializer<I>,
{
    #[inline]
    fn count(&self) -> usize {
        afl().queued_items as usize
    }

    #[inline]
    fn add(&mut self, _testcase: Testcase<I>) -> Result<CorpusId, Error> {
        unimplemented!();
    }

    #[inline]
    fn replace(&mut self, _idx: CorpusId, _testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        unimplemented!();
    }

    #[inline]
    fn remove(&mut self, _idx: CorpusId) -> Result<Testcase<I>, Error> {
        unimplemented!();
    }

    #[inline]
    fn get(&self, idx: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        let idx_usize: usize = idx.into();
        unsafe {
            let entries = self.entries.get().as_mut().unwrap();
            if !entries.contains(&idx_usize) {
                let queue_buf = std::slice::from_raw_parts_mut(afl().queue_buf, self.count());
                let entry = queue_buf[idx_usize].as_mut().unwrap();
                let fname = CStr::from_ptr((entry.fname.cast::<i8>()).as_ref().unwrap())
                    .to_str()
                    .unwrap()
                    .to_owned();

                // AFL++ queue entries are files, so we need to read them from disk.

                let path = std::path::Path::new(&fname);
                let bytes = std::fs::read(path)
                    .map_err(|e| Error::unknown(format!("Failed to read file: {}", e)))?;
                let input = D::deserialize(&bytes)?;

                let testcase = Testcase::with_filename(input, fname);
                entries.put(idx_usize, Box::new(RefCell::new(testcase)));
            }
            Ok(entries.get(&idx_usize).unwrap())
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

    fn next(&self, idx: CorpusId) -> Option<CorpusId> {
        let n: usize = idx.into();
        if n + 1 >= self.count() {
            None
        } else {
            Some(CorpusId::from(n + 1))
        }
    }

    fn prev(&self, idx: CorpusId) -> Option<CorpusId> {
        let n: usize = idx.into();
        if n == 0 {
            None
        } else {
            Some(CorpusId::from(n - 1))
        }
    }

    fn first(&self) -> Option<CorpusId> {
        if self.count() == 0 {
            None
        } else {
            Some(CorpusId::from(0usize))
        }
    }

    fn last(&self) -> Option<CorpusId> {
        if self.count() == 0 {
            None
        } else {
            Some(CorpusId::from(self.count() - 1))
        }
    }

    fn peek_free_id(&self) -> CorpusId {
        CorpusId::from(self.count())
    }

    fn get_from_all(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        self.get(id)
    }

    fn count_all(&self) -> usize {
        self.count()
    }

    fn count_disabled(&self) -> usize {
        0
    }

    fn add_disabled(&mut self, _testcase: Testcase<I>) -> Result<CorpusId, Error> {
        unimplemented!()
    }

    fn nth_from_all(&self, _nth: usize) -> CorpusId {
        todo!()
    }

    fn load_input_into(&self, _testcase: &mut Testcase<I>) -> Result<(), Error> {
        todo!()
    }

    fn store_input_from(&self, _testcase: &Testcase<I>) -> Result<(), Error> {
        todo!()
    }
}

#[allow(dead_code)]
struct LibAflBaseCustomMutator {
    state: StdState<AflCorpus, BytesInput, StdRand, AflCorpus>,
    input: BytesInput,
}

impl CustomMutator for LibAflBaseCustomMutator {
    type Error = libafl::Error;

    fn init(afl: &'static afl_state, seed: u32) -> Result<Self, Self::Error> {
        unsafe {
            AFL = Some(afl);
            let rand = StdRand::with_seed(u64::from(seed));
            let corpus = AflCorpus::default();
            let solutions = AflCorpus::default();
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

#[cfg(feature = "mutator")]
export_mutator!(LibAflBaseCustomMutator);
