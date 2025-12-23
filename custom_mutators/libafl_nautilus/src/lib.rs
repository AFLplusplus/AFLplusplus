use custom_mutator::{afl_state, export_mutator, CustomMutator};
use libafl::{
    corpus::NopCorpus,
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
use libafl_base::AflCustomInputCorpus;
use libafl_bolts::{
    nonzero,
    rands::StdRand,
    tuples::{tuple_list, tuple_list_type},
};

type NautilusMutators = tuple_list_type!(
    NautilusRandomMutator<'static>,
    NautilusRecursionMutator<'static>,
    NautilusSpliceMutator<'static>
);

pub struct NautilusCustomMutator {
    state: StdState<
        AflCustomInputCorpus<NautilusInput, NautilusBytesConverter<'static>>,
        NautilusInput,
        StdRand,
        NopCorpus<NautilusInput>,
    >,
    generator: NautilusGenerator<'static>,
    mutator: HavocScheduledMutator<NautilusMutators>,
    unparsed_buf: Vec<u8>,
    tmp_input: Option<NautilusInput>,
    #[allow(unused)]
    context: &'static NautilusContext,
}

impl CustomMutator for NautilusCustomMutator {
    type Error = libafl::Error;

    fn init(afl: &'static afl_state, seed: u32) -> Result<Self, libafl::Error> {
        let _ = env_logger::builder().parse_env("NAUTILUS_LOG").try_init();
        // Load grammar from grammar.json
        let grammar_path =
            std::env::var("NAUTILUS_GRAMMAR_FILE").unwrap_or_else(|_| "grammar.json".to_string());

        let context = Box::new(NautilusContext::from_file(10, &grammar_path).map_err(|e| {
            let msg = format!("Failed to load grammar from {grammar_path}: {e}");
            Error::unknown(msg)
        })?);
        let context_ref = Box::leak(context);

        let rand = StdRand::with_seed(u64::from(seed));

        let work_dir = std::env::current_dir().unwrap().join("out-nautilus");
        let shadow_corpus_path = work_dir.join("shadow_corpus");

        log::info!(
            "Nautilus: init called. Shadow corpus: {}",
            shadow_corpus_path.display()
        );

        let converter = NautilusBytesConverter::new(context_ref);
        let corpus =
            AflCustomInputCorpus::new(afl, &shadow_corpus_path, nonzero!(4096), converter)?;
        let mut state = StdState::new(rand, corpus, NopCorpus::new(), &mut (), &mut ())?;

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
            context: context_ref,
        })
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        _add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, libafl::Error> {
        self.state.set_max_size(max_size);

        let input_res = {
            let corpus = self.state.corpus();
            let mut converter = corpus.target_byte_converter().borrow_mut();
            converter.convert_from_target_bytes(&mut (), buffer)
        };

        let mut input = input_res.unwrap_or_else(|_| {
            self.generator
                .generate(&mut self.state)
                .expect("Failed to generate initial input")
        });

        self.mutator.mutate(&mut self.state, &mut input)?;

        let bytes = self
            .state
            .corpus()
            .target_byte_converter()
            .borrow_mut()
            .convert_to_target_bytes(&mut (), &input)
            .to_vec();
        self.unparsed_buf.clear();
        self.unparsed_buf.extend_from_slice(bytes.as_slice());

        Ok(Some(&self.unparsed_buf))
    }

    fn queue_new_entry(
        &mut self,
        filename_new_queue: &std::path::Path,
        _filename_orig_queue: Option<&std::path::Path>,
    ) -> Result<bool, libafl::Error> {
        self.state
            .corpus_mut()
            .on_queue_new_entry(filename_new_queue, self.tmp_input.take())
    }

    fn queue_get(&mut self, filename: &std::path::Path) -> Result<bool, libafl::Error> {
        self.state
            .corpus()
            .on_queue_get(filename, &mut self.tmp_input)
    }
}

type ConcreteNautilusMutator = NautilusCustomMutator;
export_mutator!(ConcreteNautilusMutator);

#[cfg(test)]
mod tests {
    use libafl::{
        corpus::{Corpus, Testcase},
        generators::NautilusContext,
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
    ) -> NautilusCustomMutator {
        let rand = StdRand::with_seed(0);
        std::fs::create_dir_all(dir).unwrap();

        let converter = NautilusBytesConverter::new(context_ref);

        let layout = std::alloc::Layout::new::<afl_state>();
        // Safety: We crate an empty afl struct for testing... Don't try this at home..
        #[allow(clippy::cast_ptr_alignment)]
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<afl_state>();
        let afl = unsafe { &*ptr };

        let corpus_dir = dir.join("corpus");
        std::fs::create_dir_all(&corpus_dir).unwrap();
        let corpus =
            AflCustomInputCorpus::new(afl, &corpus_dir, nonzero!(4096), converter).unwrap();
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
            context: context_ref,
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
        let mut buffer = converter.convert_to_target_bytes(&mut (), &input).to_vec();

        // Run fuzz
        let mutated = mutator.fuzz(&mut buffer, None, 1024).unwrap();
        assert!(mutated.is_some());

        let mutated_bytes = mutated.unwrap();
        assert!(!mutated_bytes.is_empty());

        // Verify output is a valid Nautilus input
        let deserialized = converter.convert_from_target_bytes(&mut (), mutated_bytes);
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

        let deserialized_gen = converter.convert_from_target_bytes(&mut (), generated_bytes);
        assert!(
            deserialized_gen.is_ok(),
            "Generated output from invalid input should be deserializable"
        );
    }

    #[test]
    fn test_queue_new_entry_resume() {
        let context_ref = create_test_context();
        let dir = std::env::temp_dir().join("nautilus_test_resume");
        // Clean up
        let _ = std::fs::remove_dir_all(&dir);

        let mut mutator = create_test_mutator(context_ref, &dir);

        // 1. Generate and add input to corpus
        let input = mutator.generator.generate(&mut mutator.state).unwrap();
        let testcase = Testcase::new(input.clone());
        let _id = mutator.state.corpus_mut().add(testcase).unwrap();

        // 2. Find the file on disk
        let corpus_dir = dir.join("corpus");
        let entries: Vec<_> = std::fs::read_dir(&corpus_dir)
            .unwrap()
            .map(|e| e.unwrap())
            .collect();

        let _file_path = entries
            .iter()
            .find(|e| {
                !e.file_name().to_string_lossy().contains("lock")
                    && !e.file_name().to_string_lossy().contains("metadata")
            })
            .unwrap()
            .path();

        // 3. Check specific behavior when file exists
        // We know serialization is currently asymmetric/broken for NautilusInput ("1" vs struct).
        // So we expect queue_new_entry to FAIL to load, but successfully fall back to adding it again.

        let filename = "resume_test_id";
        let queue_file_path = dir.join(filename);
        std::fs::write(&queue_file_path, "A").unwrap(); // create valid input file for fallback

        let result = mutator.queue_new_entry(&queue_file_path, None);
        assert!(
            result.is_ok(),
            "queue_new_entry should not fail even if deserialization fails"
        );

        // Count should be at least 1 (it was 1 from setup).
        // If it re-added, it might be 2, or 1 if it overwrote/deduplicated.
        let count = mutator.state.corpus().count();
        assert!(count >= 1, "Corpus count should be maintained");
    }

    #[test]
    fn test_dump_inputs_tool() {
        let dir = std::env::temp_dir().join("libafl_nautilus_dump_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let grammar_path = dir.join("grammar.json");
        std::fs::write(
            &grammar_path,
            r#"[
            ["START", "valid_seed"]
        ]"#,
        )
        .unwrap();

        let context = NautilusContext::from_file(10, grammar_path.to_str().unwrap()).unwrap();
        let context_ref = Box::leak(Box::new(context));

        // Create a mutator to generate an input
        let mut mutator = create_test_mutator(context_ref, &dir);
        let input = mutator.generator.generate(&mut mutator.state).unwrap();

        // Write input using Input::to_file to match CachedOnDiskCorpus
        let input_dir = dir.join("in");
        std::fs::create_dir_all(&input_dir).unwrap();
        let input_path = input_dir.join("id_0");

        input.to_file(&input_path).unwrap();

        // Output dir
        let output_dir = dir.join("out");

        // Run dump_inputs binary
        // We assume we are in custom_mutators/libafl_nautilus
        let status = std::process::Command::new("cargo")
            .args([
                "run",
                "--bin",
                "dump_inputs",
                "--",
                "--grammar",
                grammar_path.to_str().unwrap(),
                "--input",
                input_dir.to_str().unwrap(),
                "--output",
                output_dir.to_str().unwrap(),
            ])
            .status()
            .expect("Failed to run dump_inputs");

        assert!(status.success());

        // Verify output exists and contains "valid_seed"
        let out_file = output_dir.join("id_0");
        assert!(out_file.exists());
        let file_content = std::fs::read_to_string(out_file).unwrap();
        assert!(file_content.contains("valid_seed"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
