use custom_mutator::{afl_state, export_mutator, CustomMutator};
use libafl::{
    corpus::{Corpus, NopCorpus},
    feedbacks::nautilus::NautilusChunksMetadata,
    generators::{Generator, NautilusContext, NautilusGenerator},
    inputs::{NautilusBytesConverter, NautilusInput},
    mutators::{
        nautilus::{NautilusRandomMutator, NautilusRecursionMutator, NautilusSpliceMutator},
        scheduled::HavocScheduledMutator,
    },
    prelude::*,
    state::{HasCorpus, HasMaxSize, StdState},
    Error, HasMetadata,
};
use libafl_base::AflCorpus;
use libafl_bolts::{
    rands::StdRand,
    tuples::{tuple_list, tuple_list_type},
    AsSlice,
};

type NautilusMutators = tuple_list_type!(
    NautilusRandomMutator<'static>,
    NautilusRecursionMutator<'static>,
    NautilusSpliceMutator<'static>
);

static mut NAUTILUS_CONTEXT: Option<&'static NautilusContext> = None;

type NautilusCorpus<'a> = AflCorpus<NautilusInput, NautilusBytesConverter<'a>>;

struct NautilusCustomMutator<C>
where
    C: Corpus<NautilusInput>,
{
    state: StdState<C, NautilusInput, StdRand, NopCorpus<NautilusInput>>,
    generator: NautilusGenerator<'static>,
    mutator: HavocScheduledMutator<NautilusMutators>,
    unparsed_buf: Vec<u8>,
    tmp_input: Option<NautilusInput>,
}

impl CustomMutator for NautilusCustomMutator<NautilusCorpus<'static>> {
    type Error = libafl::Error;

    fn init(afl: &'static afl_state, seed: u32) -> Result<Self, libafl::Error> {
        // Load grammar from grammar.json
        let grammar_path =
            std::env::var("NAUTILUS_GRAMMAR_FILE").unwrap_or_else(|_| "grammar.json".to_string());

        let context = Box::new(NautilusContext::from_file(10, &grammar_path).map_err(|e| {
            let msg = format!("Failed to load grammar from {grammar_path}: {e}");
            Error::unknown(msg)
        })?);
        let context_ref = Box::leak(context);
        unsafe {
            NAUTILUS_CONTEXT = Some(context_ref);
        }

        let rand = StdRand::with_seed(u64::from(seed));

        let work_dir = std::env::current_dir().unwrap().join("out-nautilus");
        let shadow_corpus_path = work_dir.join("shadow_corpus");
        std::fs::create_dir_all(&shadow_corpus_path).ok();
        eprintln!("Nautilus: Shadow corpus path: {:?}", shadow_corpus_path);

        let converter = NautilusBytesConverter::new(context_ref);
        let corpus =
            NautilusCorpus::with_converter(afl, Some(&shadow_corpus_path), 4096, converter)?;
        let solutions = NopCorpus::new();
        let mut feedback = ();
        let mut objective = ();
        let state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)?;

        let mut state = state;
        state.add_metadata(NautilusChunksMetadata::new(
            work_dir.to_string_lossy().to_string(),
        ));

        let generator = NautilusGenerator::new(context_ref);

        let mutator = HavocScheduledMutator::new(tuple_list!(
            NautilusRandomMutator::new(context_ref),
            NautilusRecursionMutator::new(context_ref),
            NautilusSpliceMutator::new(context_ref)
        ));

        Ok(NautilusCustomMutator {
            state,
            generator,
            mutator,
            unparsed_buf: Vec::new(),
            tmp_input: None,
        })
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        _buffer: &'b mut [u8],
        _add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, libafl::Error> {
        self.state.set_max_size(max_size);

        let mut input = if let Some(input) = self.tmp_input.take() {
            input
        } else {
            self.generator.generate(&mut self.state)?
        };

        self.mutator.mutate(&mut self.state, &mut input)?;

        let bytes = self
            .state
            .corpus()
            .target_byte_converter()
            .borrow_mut()
            .to_target_bytes(&input);
        self.unparsed_buf.clear();
        self.unparsed_buf.extend_from_slice(bytes.as_slice());
        self.tmp_input = Some(input);

        Ok(Some(&self.unparsed_buf))
    }

    fn queue_new_entry(
        &mut self,
        _filename_new_queue: &std::path::Path,
        _filename_orig_queue: Option<&std::path::Path>,
    ) -> Result<bool, libafl::Error> {
        eprintln!("Nautilus: queue_new_entry called");
        if let Some(input) = self.tmp_input.take() {
            eprintln!("Nautilus: Adding input to corpus");
            let testcase = Testcase::new(input.clone());
            self.state.corpus_mut().add(testcase)?;
        } else {
            eprintln!("Nautilus: No tmp_input to add");
        }
        Ok(false)
    }
}

type ConcreteNautilusMutator = NautilusCustomMutator<NautilusCorpus<'static>>;
export_mutator!(ConcreteNautilusMutator);

#[cfg(test)]
mod tests {
    use libafl::{
        corpus::{Corpus, Testcase},
        generators::NautilusContext,
        inputs::ToTargetBytes,
        state::HasCorpus,
    };
    use libafl_bolts::rands::Rand;

    use super::*;

    fn create_test_context() -> &'static NautilusContext {
        let rules = vec![
            ("START", "{DATA}".as_bytes()),
            ("DATA", "A".as_bytes()),
            ("DATA", "B".as_bytes()),
        ];
        let context = NautilusContext::with_rules(10, &rules).unwrap();
        Box::leak(Box::new(context))
    }

    fn create_test_mutator(
        context_ref: &'static NautilusContext,
        dir: &std::path::Path,
    ) -> NautilusCustomMutator<NautilusCorpus<'static>> {
        let rand = StdRand::with_seed(0);
        std::fs::create_dir_all(dir).unwrap();

        let converter = NautilusBytesConverter::new(context_ref);

        let layout = std::alloc::Layout::new::<afl_state>();
        // Safety: We crate an empty afl struct for testing... Don't try this at home..
        #[allow(clippy::cast_ptr_alignment)]
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<afl_state>();
        let afl = unsafe { &*ptr };

        let corpus = NautilusCorpus::with_converter(afl, None, 4096, converter).unwrap();
        let solutions = NopCorpus::new();
        let mut feedback = ();
        let mut objective = ();
        let mut state =
            StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();

        state.add_metadata(NautilusChunksMetadata::new(
            dir.to_string_lossy().to_string(),
        ));

        let mutator_instance = HavocScheduledMutator::new(tuple_list!(
            NautilusRandomMutator::new(context_ref),
            NautilusRecursionMutator::new(context_ref),
            NautilusSpliceMutator::new(context_ref)
        ));

        NautilusCustomMutator {
            state,
            generator: NautilusGenerator::new(context_ref),
            mutator: mutator_instance,
            unparsed_buf: Vec::new(),
            tmp_input: None,
        }
    }

    #[test]
    fn test_splicing() {
        let context_ref = create_test_context();
        let dir = std::env::temp_dir().join("nautilus_test_splicing");
        let _ = std::fs::remove_dir_all(&dir);
        let mut mutator = create_test_mutator(context_ref, &dir);

        // Generate two distinct inputs to ensure splicing has variety
        // With seeds 0 and 1, we hopefully get different trees (A and B)
        let input1 = mutator.generator.generate(&mut mutator.state).unwrap();

        // Force a different random state for the second generation if needed,
        // but generator uses state's rand.
        // We can just loop until we get a different one or just add multiple.
        mutator.state.rand_mut().set_seed(1);
        let input2 = mutator.generator.generate(&mut mutator.state).unwrap();

        let testcase1 = Testcase::new(input1.clone());
        let testcase2 = Testcase::new(input2.clone());
        mutator.state.corpus_mut().add(testcase1).unwrap();
        mutator.state.corpus_mut().add(testcase2).unwrap();

        // Try to splice
        let mut splice_mutator = NautilusSpliceMutator::new(context_ref);

        // We need to mutate one of them.
        let mut input_to_splice = input1.clone();
        let result = splice_mutator.mutate(&mut mutator.state, &mut input_to_splice);

        assert!(result.is_ok());

        // Ensure the result is valid by unparsing
        let mut buf = Vec::new();
        input_to_splice.unparse(context_ref, &mut buf);
        assert!(!buf.is_empty());
        let s = String::from_utf8_lossy(&buf);
        assert!(s == "A" || s == "B");
    }

    #[test]
    fn test_fuzz_integration() {
        let context_ref = create_test_context();
        let dir = std::env::temp_dir().join("nautilus_test_fuzz");
        let _ = std::fs::remove_dir_all(&dir);
        let mut mutator = create_test_mutator(context_ref, &dir);
        let mut converter = NautilusBytesConverter::new(context_ref);

        // Case 1: Fuzzing with valid input
        // Generate valid initial bytes
        let input = mutator.generator.generate(&mut mutator.state).unwrap();
        let mut buffer = converter.to_target_bytes(&input).to_vec();

        // Run fuzz
        let mutated = mutator.fuzz(&mut buffer, None, 1024).unwrap();
        assert!(mutated.is_some());

        let mutated_bytes = mutated.unwrap();
        assert!(!mutated_bytes.is_empty());

        // Verify output is a valid Nautilus input
        let deserialized = converter.from_target_bytes(mutated_bytes);
        assert!(
            deserialized.is_ok(),
            "Fuzzed output should be deserializable"
        );

        // Case 2: Fuzzing with invalid input (should trigger fresh generation)
        let mut invalid_buffer = b"INVALID_GARBAGE".to_vec();
        let generated = mutator.fuzz(&mut invalid_buffer, None, 1024).unwrap();
        assert!(generated.is_some());

        let generated_bytes = generated.unwrap();
        assert!(!generated_bytes.is_empty());

        let deserialized_gen = converter.from_target_bytes(generated_bytes);
        assert!(
            deserialized_gen.is_ok(),
            "Generated output from invalid input should be deserializable"
        );
    }
}
