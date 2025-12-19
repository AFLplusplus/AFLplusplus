#![cfg(unix)]

use custom_mutator::{afl_state, export_mutator, CustomMutator};
use libafl::{
    corpus::{Corpus, NopCorpus},
    feedbacks::nautilus::NautilusChunksMetadata,
    generators::{Generator, NautilusContext, NautilusGenerator},
    inputs::{FromTargetBytes, NautilusBytesConverter, NautilusInput},
    mutators::{
        nautilus::{NautilusRandomMutator, NautilusRecursionMutator, NautilusSpliceMutator},
        scheduled::HavocScheduledMutator,
        Mutator,
    },
    state::{HasCorpus, HasMaxSize, StdState},
    Error, HasMetadata,
};
use libafl_base::AflCorpus;
use libafl_bolts::{
    nonzero,
    rands::StdRand,
    tuples::{tuple_list, tuple_list_type},
};
use lru::LruCache;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::OnceLock;
static CONTEXT: OnceLock<NautilusContext> = OnceLock::new();

type NautilusMutators = tuple_list_type!(
    NautilusRandomMutator<'static>,
    NautilusRecursionMutator<'static>,
    NautilusSpliceMutator<'static>
);

struct NautilusCustomMutator<C>
where
    C: Corpus<NautilusInput>,
{
    state: StdState<C, NautilusInput, StdRand, NopCorpus<NautilusInput>>,
    generator: NautilusGenerator<'static>,
    context: &'static NautilusContext,
    mutator: HavocScheduledMutator<NautilusMutators>,
    serialized_buf: Vec<u8>,
    cache: LruCache<Vec<u8>, NautilusInput>,
}

impl<C> NautilusCustomMutator<C>
where
    C: Corpus<NautilusInput> + Serialize + DeserializeOwned,
{
    fn fuzz_logic<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        _add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, libafl::Error> {
        self.state.set_max_size(max_size);

        // 1. Check cache
        let mut input = if let Some(cached) = self.cache.get(buffer) {
            cached.clone()
        } else {
            // 2. Try to parse
            let mut converter = NautilusBytesConverter::new(self.context);
            if let Ok(parsed) = converter.from_target_bytes(buffer) {
                self.cache.put(buffer.to_vec(), parsed.clone());
                parsed
            } else {
                // 3. Fallback to corpus or generate
                if let Some(id) = self.state.corpus().current() {
                    self.state
                        .corpus()
                        .get(*id)?
                        .borrow()
                        .input()
                        .clone()
                        .unwrap()
                } else {
                    self.generator.generate(&mut self.state)?
                }
            }
        };

        // Mutate the input
        self.mutator.mutate(&mut self.state, &mut input)?;

        // Serialize the mutated input
        self.serialized_buf.clear();
        input.unparse(self.context, &mut self.serialized_buf);
        self.cache.put(self.serialized_buf.clone(), input.clone());

        Ok(Some(&self.serialized_buf))
    }
}

impl CustomMutator
    for NautilusCustomMutator<AflCorpus<NautilusInput, NautilusBytesConverter<'static>>>
{
    type Error = libafl::Error;

    fn init(afl: &'static afl_state, seed: u32) -> Result<Self, Self::Error> {
        unsafe {
            libafl_base::set_afl_state(afl);

            // Load grammar from grammar.json in current directory or from env var
            let context_ref = CONTEXT.get_or_init(|| {
                let grammar_path = std::env::var("NAUTILUS_GRAMMAR_FILE")
                    .unwrap_or_else(|_| "grammar.json".to_string());
                NautilusContext::from_file(10, &grammar_path)
                    .map_err(|e| {
                        let err_msg = format!("Failed to load grammar from {grammar_path}: {e}");
                        Error::unknown(err_msg)
                    })
                    .expect("Failed to load grammar")
            });

            let rand = StdRand::with_seed(u64::from(seed));

            let work_dir = std::env::current_dir().unwrap().join("out-nautilus");
            let corpus_dir = work_dir.join("corpus");
            std::fs::create_dir_all(&corpus_dir)
                .map_err(|e| Error::unknown(format!("Failed to create corpus dir: {}", e)))?;

            let converter = NautilusBytesConverter::new(context_ref);
            let corpus = AflCorpus::new(Some(&corpus_dir), 4096, converter)?;
            let solutions = NopCorpus::new();
            let mut feedback = ();
            let mut objective = ();
            let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)?;

            state.add_metadata(NautilusChunksMetadata::new(
                work_dir.to_string_lossy().to_string(),
            ));

            let generator = NautilusGenerator::new(context_ref);

            let mutator = HavocScheduledMutator::new(tuple_list!(
                NautilusRandomMutator::new(context_ref),
                NautilusRecursionMutator::new(context_ref),
                NautilusSpliceMutator::new(context_ref)
            ));

            Ok(Self {
                state,
                generator,
                context: context_ref,
                mutator,
                serialized_buf: Vec::new(),
                cache: LruCache::new(nonzero!(1024)),
            })
        }
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, Self::Error> {
        self.fuzz_logic(buffer, add_buff, max_size)
    }


}

type ConcreteNautilusMutator =
    NautilusCustomMutator<AflCorpus<NautilusInput, NautilusBytesConverter<'static>>>;
export_mutator!(ConcreteNautilusMutator);

#[cfg(test)]
mod tests {

    use libafl::{
        corpus::{Corpus, Testcase},
        generators::NautilusContext,
        state::HasCorpus,
    };

    use super::*;

    fn create_test_mutator(
        context_ref: &'static NautilusContext,
        dir: &std::path::Path,
    ) -> NautilusCustomMutator<AflCorpus<NautilusInput, NautilusBytesConverter<'static>>> {
        let rand = StdRand::with_seed(0);
        std::fs::create_dir_all(dir).unwrap();
        let converter = NautilusBytesConverter::new(context_ref);
        let corpus = AflCorpus::new(Some(dir), 100, converter).unwrap();
        let solutions = NopCorpus::new();
        let mut feedback = ();
        let mut objective = ();
        let mut state =
            StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();

        state.add_metadata(NautilusChunksMetadata::new(
            "/tmp/nautilus-test".to_string(),
        ));

        let mutator_instance = HavocScheduledMutator::new(tuple_list!(
            NautilusRandomMutator::new(context_ref),
            NautilusRecursionMutator::new(context_ref),
            NautilusSpliceMutator::new(context_ref)
        ));

        NautilusCustomMutator {
            state,
            generator: NautilusGenerator::new(context_ref),
            context: context_ref,
            mutator: mutator_instance,
            serialized_buf: Vec::new(),
            cache: LruCache::new(nonzero!(128)),
        }
    }

    #[test]
    fn test_splicing() {
        let rules = vec![("START", "{DATA}".as_bytes()), ("DATA", "TEST".as_bytes())];
        let context = NautilusContext::with_rules(10, &rules).unwrap();
        let context_ref = Box::leak(Box::new(context));

        let dir = std::env::temp_dir().join("nautilus_test_splicing");
        let _ = std::fs::remove_dir_all(&dir); // Clean up previous run
        let mut mutator = create_test_mutator(context_ref, &dir);

        // Generate an input
        let mut input = mutator.generator.generate(&mut mutator.state).unwrap();

        // Add input to corpus so splicing has something to use
        let testcase = Testcase::new(input.clone());
        mutator.state.corpus_mut().add(testcase).unwrap();

        // Try to splice
        let mut splice_mutator = NautilusSpliceMutator::new(context_ref);
        let result = splice_mutator.mutate(&mut mutator.state, &mut input);

        // Splicing should succeed
        assert!(result.is_ok());
    }

    #[test]
    fn test_fuzz_fallback() {
        let rules = vec![("START", "{DATA}".as_bytes()), ("DATA", "TEST".as_bytes())];
        let context = NautilusContext::with_rules(10, &rules).unwrap();
        let context_ref = Box::leak(Box::new(context));

        let dir = std::env::temp_dir().join("nautilus_test_fallback");
        let _ = std::fs::remove_dir_all(&dir); // Clean up previous run
        let mut mutator = create_test_mutator(context_ref, &dir);

        // Case 1: Valid input buffer, not in corpus
        let input = mutator.generator.generate(&mut mutator.state).unwrap();
        let bytes = postcard::to_allocvec(&input).unwrap();
        let mut buffer = bytes.clone();

        let mutated = mutator.fuzz_logic(&mut buffer, None, 1024).unwrap();
        assert!(mutated.is_some());

        // Case 2: Invalid input buffer, should generate new
        let mut buffer = b"INVALID".to_vec();
        let mutated = mutator.fuzz_logic(&mut buffer, None, 1024).unwrap();
        assert!(mutated.is_some());

        // Verify that the mutated output is not empty
        let mutated_bytes = mutated.unwrap();
        assert!(!mutated_bytes.is_empty());
        // We can't easily verify it's a valid NautilusInput since we don't have the parser here
        // and it's raw bytes now, not postcard.
    }
}
