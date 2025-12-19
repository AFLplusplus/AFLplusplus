#![cfg(unix)]

use std::{
    cell::{RefCell, UnsafeCell},
    ffi::CStr,
    num::NonZeroUsize,
};

#[cfg(feature = "mutator")]
use custom_mutator::export_mutator;
use custom_mutator::{CustomMutator, afl_state};
use libafl::{
    Error, HasMetadata,
    corpus::{CachedOnDiskCorpus, Corpus, CorpusId, Testcase},
    inputs::{BytesInput, FromTargetBytes, NopFromTargetBytes},
    mutators::{
        HavocScheduledMutator, Mutator, Tokens, havoc_mutations::havoc_mutations, tokens_mutations,
    },
    state::{HasMaxSize, StdState},
};
use libafl_bolts::{rands::StdRand, tuples::Merge};
use lru::LruCache;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

static mut AFL: Option<&'static afl_state> = None;

/// Set the AFL state global.
/// # Safety
/// This function is unsafe because it sets a static mutable variable.
pub unsafe fn set_afl_state(afl: &'static afl_state) {
    unsafe {
        AFL = Some(afl);
    }
}

#[derive(Debug)]
pub struct AflCorpus<I = BytesInput, D = NopFromTargetBytes> {
    inner: UnsafeCell<Option<CachedOnDiskCorpus<I>>>,
    cache: UnsafeCell<LruCache<CorpusId, RefCell<Testcase<I>>>>,
    current: UnsafeCell<Option<CorpusId>>,
    deserializer: UnsafeCell<D>,
}

impl<I, D> AflCorpus<I, D> {
    pub fn new(
        dir_path: Option<&std::path::Path>,
        cache_max_len: usize,
        deserializer: D,
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
            inner: UnsafeCell::new(inner),
            cache: UnsafeCell::new(LruCache::new(cap)),
            current: UnsafeCell::new(None),
            deserializer: UnsafeCell::new(deserializer),
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
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            if inner.is_some() {
                panic!("AflCorpus cloning with inner corpus not fully supported yet");
            }

            let cap = self.cache.get().as_ref().unwrap().cap();
            Self {
                inner: UnsafeCell::new(None),
                cache: UnsafeCell::new(LruCache::new(cap)),
                current: UnsafeCell::new(None),
                deserializer: UnsafeCell::new(self.deserializer.get().as_ref().unwrap().clone()),
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
    D: FromTargetBytes<I>,
{
    #[inline]
    fn count(&self) -> usize {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            let local_count = if let Some(inner) = inner {
                inner.count()
            } else {
                0
            };
            if let Some(afl) = AFL {
                std::cmp::max(local_count, afl.queued_items as usize)
            } else {
                local_count
            }
        }
    }

    fn count_disabled(&self) -> usize {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            if let Some(inner) = inner {
                inner.count_disabled()
            } else {
                0
            }
        }
    }

    #[inline]
    fn count_all(&self) -> usize {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            let local_count = if let Some(inner) = inner {
                inner.count_all()
            } else {
                0
            };
            if let Some(afl) = AFL {
                std::cmp::max(local_count, afl.queued_items as usize)
            } else {
                local_count
            }
        }
    }

    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        unsafe {
            let inner = self.inner.get().as_mut().unwrap();
            if let Some(inner) = inner {
                inner.add(testcase)
            } else {
                let id = CorpusId::from(self.count());
                self.cache
                    .get()
                    .as_mut()
                    .unwrap()
                    .put(id, RefCell::new(testcase));
                Ok(id)
            }
        }
    }

    #[inline]
    fn add_disabled(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        unsafe {
            let inner = self.inner.get().as_mut().unwrap();
            if let Some(inner) = inner {
                inner.add_disabled(testcase)
            } else {
                let id = CorpusId::from(self.count());
                self.cache
                    .get()
                    .as_mut()
                    .unwrap()
                    .put(id, RefCell::new(testcase));
                Ok(id)
            }
        }
    }

    #[inline]
    fn replace(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        unsafe {
            let inner = self.inner.get().as_mut().unwrap();
            if let Some(inner) = inner {
                inner.replace(id, testcase)
            } else {
                let old = self
                    .cache
                    .get()
                    .as_mut()
                    .unwrap()
                    .put(id, RefCell::new(testcase));
                old.map(|r| r.into_inner())
                    .ok_or_else(|| Error::key_not_found(format!("CorpusId {id} not found")))
            }
        }
    }

    fn remove(&mut self, id: CorpusId) -> Result<Testcase<I>, Error> {
        unsafe {
            let inner = self.inner.get().as_mut().unwrap();
            if let Some(inner) = inner {
                inner.remove(id)
            } else {
                self.cache
                    .get()
                    .as_mut()
                    .unwrap()
                    .pop(&id)
                    .map(|r| r.into_inner())
                    .ok_or_else(|| Error::key_not_found(format!("CorpusId {id} not found")))
            }
        }
    }

    #[inline]
    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        unsafe {
            let inner = self.inner.get().as_mut().unwrap();

            if let Some(inner) = inner {
                return inner.get(id);
            }

            // Check cache first
            if let Some(entry) = self.cache.get().as_mut().unwrap().get(&id) {
                return Ok(&*(entry as *const _));
            }

            // Not in cache, try to fetch from AFL
            if let Some(afl) = AFL {
                let afl_count = afl.queued_items as usize;
                let i = id.0;

                if i >= afl_count {
                    return Err(Error::key_not_found(format!(
                        "CorpusId {} not found in AFL++ queue (count {})",
                        i, afl_count
                    )));
                }

                let queue_buf = std::slice::from_raw_parts(afl.queue_buf, afl_count);
                let entry = queue_buf[i].as_ref().unwrap();
                let fname_cstr = CStr::from_ptr(entry.fname.cast::<i8>());
                let fname_str = fname_cstr.to_str().unwrap();
                let fname = std::path::Path::new(fname_str)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned();

                let path = std::path::Path::new(fname_str);
                let bytes = std::fs::read(path)
                    .map_err(|e| Error::unknown(format!("Failed to read file: {}", e)))?;

                let input = self
                    .deserializer
                    .get()
                    .as_mut()
                    .unwrap()
                    .from_target_bytes(&bytes)?;

                let testcase = Testcase::with_filename(input, fname);

                // Add to cache
                self.cache
                    .get()
                    .as_mut()
                    .unwrap()
                    .put(id, RefCell::new(testcase));

                // Return reference
                let entry = self.cache.get().as_mut().unwrap().get(&id).unwrap();
                Ok(&*(entry as *const _))
            } else {
                Err(Error::key_not_found(format!(
                    "CorpusId {id} not found and AFL not available"
                )))
            }
        }
    }

    #[inline]
    fn get_from_all(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        self.get(id)
    }

    #[inline]
    fn current(&self) -> &Option<CorpusId> {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            if let Some(inner) = inner {
                inner.current()
            } else {
                self.current.get().as_ref().unwrap()
            }
        }
    }

    #[inline]
    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        unsafe {
            let inner = self.inner.get().as_mut().unwrap();
            if let Some(inner) = inner {
                inner.current_mut()
            } else {
                self.current.get().as_mut().unwrap()
            }
        }
    }

    #[inline]
    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            if let Some(inner) = inner {
                inner.next(id)
            } else if id.0 + 1 < self.count() {
                Some(CorpusId::from(id.0 + 1))
            } else {
                None
            }
        }
    }

    #[inline]
    fn peek_free_id(&self) -> CorpusId {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            if let Some(inner) = inner {
                inner.peek_free_id()
            } else {
                CorpusId::from(self.count())
            }
        }
    }

    #[inline]
    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            if let Some(inner) = inner {
                inner.prev(id)
            } else if id.0 > 0 {
                Some(CorpusId::from(id.0 - 1))
            } else {
                None
            }
        }
    }

    #[inline]
    fn first(&self) -> Option<CorpusId> {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            if let Some(inner) = inner {
                inner.first()
            } else if self.count() > 0 {
                Some(CorpusId::from(0usize))
            } else {
                None
            }
        }
    }

    #[inline]
    fn last(&self) -> Option<CorpusId> {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            if let Some(inner) = inner {
                inner.last()
            } else if self.count() > 0 {
                Some(CorpusId::from(self.count() - 1))
            } else {
                None
            }
        }
    }

    #[inline]
    fn nth(&self, nth: usize) -> CorpusId {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            if let Some(inner) = inner {
                inner.nth(nth)
            } else {
                CorpusId::from(nth)
            }
        }
    }

    #[inline]
    fn nth_from_all(&self, nth: usize) -> CorpusId {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            if let Some(inner) = inner {
                inner.nth_from_all(nth)
            } else {
                CorpusId::from(nth)
            }
        }
    }

    #[inline]
    fn load_input_into(&self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            if let Some(inner) = inner {
                inner.load_input_into(testcase)
            } else {
                if testcase.input().is_none()
                    && let Some(filename) = testcase.filename()
                {
                    let path = std::path::Path::new(filename);
                    let bytes = std::fs::read(path)
                        .map_err(|e| Error::unknown(format!("Failed to read file: {}", e)))?;
                    let input = self
                        .deserializer
                        .get()
                        .as_mut()
                        .unwrap()
                        .from_target_bytes(&bytes)?;
                    testcase.set_input(input);
                }
                Ok(())
            }
        }
    }

    #[inline]
    fn store_input_from(&self, testcase: &Testcase<I>) -> Result<(), Error> {
        unsafe {
            let inner = self.inner.get().as_ref().unwrap();
            if let Some(inner) = inner {
                inner.store_input_from(testcase)
            } else {
                // We don't store to disk if we are just wrapping AFL (AFL handles storage).
                Ok(())
            }
        }
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

            let corpus_dir = std::env::temp_dir().join("libafl_base_corpus");
            std::fs::create_dir_all(&corpus_dir).ok();
            let corpus = AflCorpus::new(Some(&corpus_dir), 4096, NopFromTargetBytes).unwrap();
            let solutions_dir = std::env::temp_dir().join("libafl_base_solutions");
            std::fs::create_dir_all(&solutions_dir).ok();
            let solutions = AflCorpus::new(Some(&solutions_dir), 4096, NopFromTargetBytes).unwrap();
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

        self.input.as_mut().clear();
        self.input.as_mut().extend_from_slice(buffer);

        let mut mutator = HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
        mutator.mutate(&mut self.state, &mut self.input)?;
        Ok(Some(self.input.as_ref()))
    }
}

#[cfg(feature = "mutator")]
export_mutator!(LibAflBaseCustomMutator);

#[cfg(test)]
mod tests {
    use libafl::{corpus::Corpus, inputs::HasTargetBytes, state::HasCorpus};
    use libafl_bolts::AsSlice;

    use super::*;

    #[test]
    fn test_libafl_base_mutator() {
        let rand = StdRand::with_seed(0);
        let corpus_dir = std::env::temp_dir().join("libafl_base_test_corpus");
        std::fs::create_dir_all(&corpus_dir).ok();
        let corpus = AflCorpus::new(Some(&corpus_dir), 4096, NopFromTargetBytes).unwrap();
        let solutions_dir = std::env::temp_dir().join("libafl_base_test_solutions");
        std::fs::create_dir_all(&solutions_dir).ok();
        let solutions = AflCorpus::new(Some(&solutions_dir), 4096, NopFromTargetBytes).unwrap();
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
