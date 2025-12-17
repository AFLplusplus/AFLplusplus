#![cfg(unix)]

use custom_mutator::{afl_state, export_mutator, CustomMutator};
use libafl::{
    corpus::{Corpus, NopCorpus},
    feedbacks::nautilus::NautilusChunksMetadata,
    generators::{Generator, NautilusContext, NautilusGenerator},
    inputs::NautilusInput,
    mutators::{
        nautilus::{NautilusRandomMutator, NautilusRecursionMutator, NautilusSpliceMutator},
        scheduled::HavocScheduledMutator,
        Mutator,
    },
    state::{HasMaxSize, StdState},
    Error, HasMetadata,
};
use libafl_base::{AflCorpus, AflStructDeserializer};
use libafl_bolts::{
    rands::StdRand,
    tuples::{tuple_list, tuple_list_type},
};
use serde::{de::DeserializeOwned, Serialize};

static mut AFL: Option<&'static afl_state> = None;

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
    unparsed_buf: Vec<u8>,
}

impl<C> CustomMutator for NautilusCustomMutator<C>
where
    C: Corpus<NautilusInput> + Default + Serialize + DeserializeOwned,
{
    type Error = libafl::Error;

    fn init(afl: &'static afl_state, seed: u32) -> Result<Self, Self::Error> {
        unsafe {
            AFL = Some(afl);

            // Load grammar from grammar.json in current directory or from env var
            let grammar_path = std::env::var("NAUTILUS_GRAMMAR_FILE")
                .unwrap_or_else(|_| "grammar.json".to_string());
            // We leak the context to get 'static lifetime
            let context = Box::new(NautilusContext::from_file(10, &grammar_path).map_err(|e| {
                let err_msg = format!("Failed to load grammar from {grammar_path}: {e}");
                Error::unknown(err_msg)
            })?);
            let context_ref = Box::leak(context);

            let rand = StdRand::with_seed(u64::from(seed));
            let corpus = C::default();
            let solutions = NopCorpus::new();
            let mut feedback = ();
            let mut objective = ();
            let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)?;

            let work_dir = std::env::current_dir().unwrap().join("out-nautilus");

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
                unparsed_buf: Vec::new(),
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

        // Try to deserialize the buffer as a NautilusInput
        let mut input = if let Ok(input) = postcard::from_bytes::<NautilusInput>(buffer) {
            input
        } else {
            #[cfg(feature = "json")]
            {
                if let Ok(input) = serde_json::from_slice::<NautilusInput>(buffer) {
                    input
                } else {
                    self.generator.generate(&mut self.state)?
                }
            }
            #[cfg(not(feature = "json"))]
            {
                self.generator.generate(&mut self.state)?
            }
        };

        // Mutate the input
        self.mutator.mutate(&mut self.state, &mut input)?;

        // Serialize the mutated input
        #[cfg(feature = "json")]
        {
            self.serialized_buf = serde_json::to_vec(&input)
                .map_err(|e| Error::unknown(format!("Failed to serialize tree to JSON: {}", e)))?;
        }

        #[cfg(not(feature = "json"))]
        {
            self.serialized_buf = postcard::to_allocvec(&input).map_err(|e| {
                Error::unknown(format!("Failed to serialize tree to Postcard: {}", e))
            })?;
        }

        Ok(Some(&self.serialized_buf))
    }

    fn post_process<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
    ) -> Result<Option<&'b [u8]>, Self::Error> {
        // Try to deserialize the buffer
        let input_opt = postcard::from_bytes::<NautilusInput>(buffer).ok();
        #[cfg(feature = "json")]
        let input_opt = if input_opt.is_none() {
            serde_json::from_slice::<NautilusInput>(buffer).ok()
        } else {
            input_opt
        };

        if let Some(input) = input_opt {
            // Unparse the tree to bytes
            self.unparsed_buf.clear();
            input.unparse(self.context, &mut self.unparsed_buf);
            Ok(Some(&self.unparsed_buf))
        } else {
            // If we can't deserialize, return an error
            Err(Error::unknown(
                "Failed to deserialize Nautilus tree in post_process",
            ))
        }
    }
}

type ConcreteNautilusMutator =
    NautilusCustomMutator<AflCorpus<NautilusInput, AflStructDeserializer>>;
export_mutator!(ConcreteNautilusMutator);

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use libafl::{
        corpus::{Corpus, CorpusId, InMemoryCorpus, Testcase},
        generators::NautilusContext,
        state::HasCorpus,
        Error,
    };
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Serialize, Deserialize)]
    struct TestCorpus(InMemoryCorpus<NautilusInput>);

    impl Default for TestCorpus {
        fn default() -> Self {
            Self(InMemoryCorpus::new())
        }
    }

    impl Corpus<NautilusInput> for TestCorpus {
        fn count(&self) -> usize {
            self.0.count()
        }

        fn count_all(&self) -> usize {
            self.0.count_all()
        }

        fn count_disabled(&self) -> usize {
            self.0.count_disabled()
        }

        fn add(&mut self, testcase: Testcase<NautilusInput>) -> Result<CorpusId, Error> {
            self.0.add(testcase)
        }

        fn add_disabled(&mut self, testcase: Testcase<NautilusInput>) -> Result<CorpusId, Error> {
            self.0.add_disabled(testcase)
        }

        fn replace(
            &mut self,
            idx: CorpusId,
            testcase: Testcase<NautilusInput>,
        ) -> Result<Testcase<NautilusInput>, Error> {
            self.0.replace(idx, testcase)
        }

        fn remove(&mut self, idx: CorpusId) -> Result<Testcase<NautilusInput>, Error> {
            self.0.remove(idx)
        }

        fn get(&self, idx: CorpusId) -> Result<&RefCell<Testcase<NautilusInput>>, Error> {
            self.0.get(idx)
        }

        fn current(&self) -> &Option<CorpusId> {
            self.0.current()
        }

        fn current_mut(&mut self) -> &mut Option<CorpusId> {
            self.0.current_mut()
        }

        fn next(&self, idx: CorpusId) -> Option<CorpusId> {
            self.0.next(idx)
        }

        fn prev(&self, idx: CorpusId) -> Option<CorpusId> {
            self.0.prev(idx)
        }

        fn first(&self) -> Option<CorpusId> {
            self.0.first()
        }

        fn last(&self) -> Option<CorpusId> {
            self.0.last()
        }

        fn peek_free_id(&self) -> CorpusId {
            self.0.peek_free_id()
        }

        fn get_from_all(&self, id: CorpusId) -> Result<&RefCell<Testcase<NautilusInput>>, Error> {
            self.0.get_from_all(id)
        }

        fn nth_from_all(&self, nth: usize) -> CorpusId {
            self.0.nth_from_all(nth)
        }

        fn load_input_into(&self, testcase: &mut Testcase<NautilusInput>) -> Result<(), Error> {
            self.0.load_input_into(testcase)
        }

        fn store_input_from(&self, testcase: &Testcase<NautilusInput>) -> Result<(), Error> {
            self.0.store_input_from(testcase)
        }
    }

    fn create_test_mutator(
        context_ref: &'static NautilusContext,
    ) -> NautilusCustomMutator<TestCorpus> {
        let rand = StdRand::with_seed(0);
        let corpus = TestCorpus::default();
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
            unparsed_buf: Vec::new(),
        }
    }

    #[test]
    fn test_post_process_postcard() {
        let rules = vec![("START", "{DATA}".as_bytes()), ("DATA", "TEST".as_bytes())];
        let context = NautilusContext::with_rules(10, &rules).unwrap();
        let context_ref = Box::leak(Box::new(context));

        let mut mutator = create_test_mutator(context_ref);

        // Generate an input
        let input = mutator.generator.generate(&mut mutator.state).unwrap();
        // Serialize with postcard
        let bytes = postcard::to_allocvec(&input).unwrap();

        // Call post_process
        let mut buffer = bytes.clone();
        let result = mutator.post_process(&mut buffer).unwrap().unwrap();

        // Verify result is "TEST"
        assert_eq!(result, b"TEST");
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_post_process_json() {
        let rules = vec![("START", "{DATA}".as_bytes()), ("DATA", "TEST".as_bytes())];
        let context = NautilusContext::with_rules(10, &rules).unwrap();
        let context_ref = Box::leak(Box::new(context));

        let mut mutator = create_test_mutator(context_ref);

        // Generate an input
        let input = mutator.generator.generate(&mut mutator.state).unwrap();
        // Serialize with JSON
        let bytes = serde_json::to_vec(&input).unwrap();

        // Call post_process
        let mut buffer = bytes.clone();
        let result = mutator.post_process(&mut buffer).unwrap().unwrap();

        // Verify result is "TEST"
        assert_eq!(result, b"TEST");
    }

    #[test]
    fn test_post_process_raw() {
        let rules = vec![("START", "A".as_bytes())];
        let context = NautilusContext::with_rules(10, &rules).unwrap();
        let context_ref = Box::leak(Box::new(context));

        let mut mutator = create_test_mutator(context_ref);

        let mut buffer = b"RAW_BYTES".to_vec();
        let result = mutator.post_process(&mut buffer);

        // Verify result is an error
        assert!(result.is_err());
    }

    #[test]
    fn test_splicing() {
        let rules = vec![("START", "{DATA}".as_bytes()), ("DATA", "TEST".as_bytes())];
        let context = NautilusContext::with_rules(10, &rules).unwrap();
        let context_ref = Box::leak(Box::new(context));

        let mut mutator = create_test_mutator(context_ref);

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
}
