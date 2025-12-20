#![cfg(unix)]

use std::{cell::RefCell, ffi::CStr, num::NonZeroUsize};

#[cfg(feature = "mutator")]
use custom_mutator::{CustomMutator, export_mutator};
use custom_mutator::{afl_state, queue_entry};
use libafl::{
    Error,
    corpus::{CachedOnDiskCorpus, Corpus, CorpusId, Testcase},
    inputs::{BytesInput, FromTargetBytes, HasTargetBytes, NopFromTargetBytes},
    state::HasCorpus,
};
#[cfg(feature = "mutator")]
use libafl::{
    HasMetadata,
    mutators::{
        HavocScheduledMutator, Mutator, Tokens, havoc_mutations::havoc_mutations, tokens_mutations,
    },
    state::{HasMaxSize, StdState},
};
use libafl_bolts::AsSlice;
#[cfg(feature = "mutator")]
use libafl_bolts::{rands::StdRand, tuples::Merge};
use lru::LruCache;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
pub struct AflCorpus<I = BytesInput, D = NopFromTargetBytes> {
    inner: Option<CachedOnDiskCorpus<I>>,
    cache: RefCell<LruCache<CorpusId, Box<RefCell<Testcase<I>>>>>,
    current: Option<CorpusId>,
    target_byte_converter: RefCell<D>,
    afl: &'static afl_state,
}

impl<I, D> AflCorpus<I, D> {
    /// Create a new `AflCorpus` with the given `afl_state` and cache size.
    ///
    /// # Errors
    /// Returns an error if the corpus directory cannot be read or initialized.
    pub fn new(afl: &'static afl_state, cache_max_len: usize) -> Result<Self, Error>
    where
        D: Default,
    {
        Self::with_converter(afl, None, cache_max_len, D::default())
    }

    /// Create a new `AflCorpus` with a custom converter and optional directory path.
    ///
    /// # Errors
    /// Returns an error if the corpus directory cannot be read or initialized.
    ///
    /// # Panics
    /// Panics if `cache_max_len` logic fails to create a `NonZeroUsize` (should not happen).
    pub fn with_converter(
        afl: &'static afl_state,
        dir_path: Option<&std::path::Path>,
        cache_max_len: usize,
        converter: D,
    ) -> Result<Self, Error> {
        let inner = if let Some(dir_path) = dir_path {
            Some(CachedOnDiskCorpus::new(dir_path, cache_max_len)?)
        } else {
            None
        };
        let cap = NonZeroUsize::new(if cache_max_len == 0 {
            10
        } else {
            cache_max_len
        })
        .unwrap();
        Ok(Self {
            inner,
            cache: RefCell::new(LruCache::new(cap)),
            current: None,
            target_byte_converter: RefCell::new(converter),
            afl,
        })
    }
}

impl<I, D> Clone for AflCorpus<I, D>
where
    I: Clone,
    D: Clone,
{
    fn clone(&self) -> Self {
        // Create a new empty cache.
        if self.inner.is_some() {
            unimplemented!("AflCorpus cloning with inner corpus not supported");
        }

        let cap = self.cache.borrow().cap();
        Self {
            inner: None,
            cache: RefCell::new(LruCache::new(cap)),
            current: None,
            target_byte_converter: RefCell::new(self.target_byte_converter.borrow().clone()),
            afl: self.afl,
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
    fn deserialize<D_>(_target_byte_converter: D_) -> Result<Self, D_::Error>
    where
        D_: Deserializer<'de>,
    {
        unimplemented!();
    }
}

impl<I, D> AflCorpus<I, D> {
    #[inline]
    pub fn target_byte_converter(&self) -> &RefCell<D> {
        &self.target_byte_converter
    }
}

impl<I, D> Corpus<I> for AflCorpus<I, D>
where
    I: libafl::inputs::Input + Clone,
    D: FromTargetBytes<I>,
{
    #[inline]
    fn count(&self) -> usize {
        let local_count = if let Some(inner) = self.inner.as_ref() {
            inner.count()
        } else {
            0
        };
        std::cmp::max(local_count, self.afl.queued_items as usize)
    }

    fn count_disabled(&self) -> usize {
        if let Some(inner) = self.inner.as_ref() {
            inner.count_disabled()
        } else {
            0
        }
    }

    #[inline]
    fn count_all(&self) -> usize {
        let local_count = if let Some(inner) = self.inner.as_ref() {
            inner.count_all()
        } else {
            0
        };
        std::cmp::max(local_count, self.afl.queued_items as usize)
    }

    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        if let Some(inner) = self.inner.as_mut() {
            return inner.add(testcase);
        }
        let id = CorpusId::from(self.count());
        self.cache
            .borrow_mut()
            .put(id, Box::new(RefCell::new(testcase)));
        Ok(id)
    }

    #[inline]
    fn add_disabled(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        if let Some(inner) = self.inner.as_mut() {
            return inner.add_disabled(testcase);
        }
        let id = CorpusId::from(self.count());
        self.cache
            .borrow_mut()
            .put(id, Box::new(RefCell::new(testcase)));
        Ok(id)
    }

    #[inline]
    fn replace(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        if let Some(inner) = self.inner.as_mut() {
            inner.replace(id, testcase)
        } else {
            let old = self
                .cache
                .borrow_mut()
                .put(id, Box::new(RefCell::new(testcase)));
            old.map(|b| (*b).into_inner())
                .ok_or_else(|| Error::key_not_found(format!("CorpusId {id} not found")))
        }
    }

    fn remove(&mut self, id: CorpusId) -> Result<Testcase<I>, Error> {
        if let Some(inner) = self.inner.as_mut() {
            inner.remove(id)
        } else {
            self.cache
                .borrow_mut()
                .pop(&id)
                .map(|b| (*b).into_inner())
                .ok_or_else(|| Error::key_not_found(format!("CorpusId {id} not found")))
        }
    }

    #[inline]
    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        // Check cache first
        let cache_ptr = self.cache.as_ptr();
        // SAFETY: We access the cache via raw pointer. The `Box` ensures that the `RefCell` address
        // is stable even if the `LruCache` rebalances/moves elements.
        // We still rely on the entry NOT being evicted while the reference is held.
        if let Some(entry) = unsafe { (*cache_ptr).get(&id) } {
            return Ok(&**entry);
        }

        // Try inner corpus directly
        if let Some(inner) = self.inner.as_ref()
            && let Ok(val) = inner.get(id)
        {
            return Ok(val);
        }

        // Not in cache, try to fetch from AFL
        let afl = self.afl;
        let afl_count = afl.queued_items as usize;
        let i = id.0;

        if i >= afl_count {
            return Err(Error::key_not_found(format!(
                "CorpusId {i} not found in AFL++ queue (count {afl_count})"
            )));
        }

        let queue_buf: &[*mut queue_entry] =
            unsafe { std::slice::from_raw_parts(afl.queue_buf, afl_count) };
        let entry = unsafe { queue_buf[i].as_ref().unwrap() };
        let fname_cstr = unsafe { CStr::from_ptr(entry.fname.cast::<i8>()) };
        let filename_str = fname_cstr.to_str().unwrap();
        let fname = std::path::Path::new(filename_str)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        let path = std::path::Path::new(filename_str);
        let bytes =
            std::fs::read(path).map_err(|e| Error::unknown(format!("Failed to read file: {e}")))?;

        let input = self
            .target_byte_converter
            .borrow_mut()
            .from_target_bytes(&bytes)?;

        let testcase = Testcase::with_filename(input, fname);

        // Add to cache
        // SAFETY: We are manually managing the RefCell pointer.
        unsafe {
            (*cache_ptr).put(id, Box::new(RefCell::new(testcase.clone())));
        }

        // Return reference
        // SAFETY: We return a reference to the item in the Box.
        unsafe {
            let entry = (*cache_ptr).get(&id).unwrap();
            Ok(&**entry)
        }
    }

    #[inline]
    fn get_from_all(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        self.get(id)
    }

    #[inline]
    fn current(&self) -> &Option<CorpusId> {
        &self.current
    }

    #[inline]
    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        &mut self.current
    }

    #[inline]
    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        if let Some(inner) = self.inner.as_ref() {
            inner.next(id)
        } else if id.0 + 1 < self.count() {
            Some(CorpusId::from(id.0 + 1))
        } else {
            None
        }
    }

    #[inline]
    fn peek_free_id(&self) -> CorpusId {
        if let Some(inner) = self.inner.as_ref() {
            inner.peek_free_id()
        } else {
            CorpusId::from(self.count())
        }
    }

    #[inline]
    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        if let Some(inner) = self.inner.as_ref() {
            inner.prev(id)
        } else if id.0 > 0 {
            Some(CorpusId::from(id.0 - 1))
        } else {
            None
        }
    }

    #[inline]
    fn first(&self) -> Option<CorpusId> {
        if let Some(inner) = self.inner.as_ref() {
            inner.first()
        } else if self.count() > 0 {
            Some(CorpusId::from(0usize))
        } else {
            None
        }
    }

    #[inline]
    fn last(&self) -> Option<CorpusId> {
        if let Some(inner) = self.inner.as_ref() {
            inner.last()
        } else if self.count() > 0 {
            Some(CorpusId::from(self.count() - 1))
        } else {
            None
        }
    }

    #[inline]
    fn nth(&self, nth: usize) -> CorpusId {
        if let Some(inner) = self.inner.as_ref() {
            inner.nth(nth)
        } else {
            CorpusId::from(nth)
        }
    }

    #[inline]
    fn nth_from_all(&self, nth: usize) -> CorpusId {
        if let Some(inner) = self.inner.as_ref() {
            inner.nth_from_all(nth)
        } else {
            CorpusId::from(nth)
        }
    }

    #[inline]
    fn load_input_into(&self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        if let Some(inner) = self.inner.as_ref() {
            inner.load_input_into(testcase)
        } else {
            if testcase.input().is_none()
                && let Some(filename) = testcase.filename()
            {
                let path = std::path::Path::new(filename);
                let bytes = std::fs::read(path)
                    .map_err(|e| Error::unknown(format!("Failed to read file: {e}")))?;
                let input = self
                    .target_byte_converter
                    .borrow_mut()
                    .from_target_bytes(&bytes)?;
                testcase.set_input(input);
            }
            Ok(())
        }
    }

    #[inline]
    fn store_input_from(&self, testcase: &Testcase<I>) -> Result<(), Error> {
        if let Some(inner) = self.inner.as_ref() {
            inner.store_input_from(testcase)
        } else {
            // We don't store to disk if we are just wrapping AFL (AFL handles storage).
            Ok(())
        }
    }
}

#[cfg(feature = "mutator")]
struct LibAflBaseCustomMutator {
    state: StdState<AflCorpus, BytesInput, StdRand, AflCorpus>,
    input: BytesInput,
}

#[cfg(feature = "mutator")]
impl CustomMutator for LibAflBaseCustomMutator {
    type Error = libafl::Error;

    fn init(afl: &'static afl_state, seed: u32) -> Result<Self, Self::Error> {
        let rand = StdRand::with_seed(u64::from(seed));

        let corpus = AflCorpus::new(afl, 4096).unwrap();
        let solutions = AflCorpus::new(afl, 4096).unwrap();
        let mut feedback = ();
        let mut objective = ();
        let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)?;

        // Accessing raw pointers from afl_state requires unsafe
        let extras = unsafe { std::slice::from_raw_parts(afl.extras, afl.extras_cnt as usize) };
        let mut tokens = vec![];
        for extra in extras {
            let data = unsafe { std::slice::from_raw_parts(extra.data, extra.len as usize) };
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

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        _add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, Self::Error> {
        self.state.set_max_size(max_size);

        self.input.as_mut().clear();
        self.input.as_mut().extend_from_slice(buffer);

        let mut mutator = HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
        mutator.mutate(&mut self.state, &mut self.input)?;
        Ok(Some(self.input.as_ref()))
    }

    fn queue_new_entry(
        &mut self,
        _filename_new_queue: &std::path::Path,
        _filename_orig_queue: Option<&std::path::Path>,
    ) -> Result<bool, Self::Error> {
        // We received a new entry from AFL++.
        let input = BytesInput::new(self.input.target_bytes().as_slice().to_vec());
        let testcase = Testcase::new(input);
        self.state.corpus_mut().add(testcase)?;
        Ok(false)
    }
}

#[cfg(feature = "mutator")]
export_mutator!(LibAflBaseCustomMutator);

#[cfg(test)]
#[cfg(feature = "mutator")]
mod tests {
    use libafl::{corpus::Corpus, inputs::HasTargetBytes, state::HasCorpus};
    use libafl_bolts::AsSlice;

    use super::*;

    #[test]
    fn test_libafl_base_mutator() {
        let rand = StdRand::with_seed(0);

        let layout = std::alloc::Layout::new::<afl_state>();
        // Safety: We generate an empty AFL struct for testing. Don't try this at home.
        #[allow(clippy::cast_ptr_alignment)]
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<afl_state>();
        let afl = unsafe { &*ptr };

        let corpus_dir = std::env::temp_dir().join("libafl_base_test_corpus");
        std::fs::create_dir_all(&corpus_dir).ok();
        let corpus =
            AflCorpus::with_converter(afl, Some(&corpus_dir), 4096, NopFromTargetBytes).unwrap();
        let solutions_dir = std::env::temp_dir().join("libafl_base_test_solutions");
        std::fs::create_dir_all(&solutions_dir).ok();
        let solutions =
            AflCorpus::with_converter(afl, Some(&solutions_dir), 4096, NopFromTargetBytes).unwrap();
        let mut feedback = ();
        let mut objective = ();
        let mut state =
            StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();

        // Add a dummy entry to corpus so mutations that require it (like Splice) don't panic
        let dummy_input = BytesInput::new(b"dummy".to_vec());
        let testcase = Testcase::new(dummy_input);
        state.corpus_mut().add(testcase).unwrap();

        let mut mutator = LibAflBaseCustomMutator {
            state,
            input: BytesInput::new(vec![]),
        };

        let mut buffer = b"test".to_vec();
        let mutated_bytes = mutator
            .fuzz(&mut buffer, None, 1024)
            .unwrap()
            .unwrap()
            .to_vec();

        // The returned bytes should match the internal input state
        assert_eq!(
            mutated_bytes.as_slice(),
            mutator.input.target_bytes().as_slice()
        );
        // We verified it didn't panic and accepted the buffer.
    }
}
