//! A tool to dump serialized Nautilus inputs to unparsed bytes.
use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::Parser;
use libafl::{
    generators::NautilusContext,
    inputs::{Input, NautilusInput},
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the grammar file (JSON)
    #[arg(short, long)]
    grammar: PathBuf,

    /// Directory containing serialized inputs
    #[arg(short, long)]
    input: PathBuf,

    /// Output directory for unparsed bytes
    #[arg(short, long)]
    output: PathBuf,
}

fn main() {
    let args = Args::parse();

    let grammar_path = &args.grammar;
    let input_dir = &args.input;
    let output_dir = &args.output;

    println!("Loading grammar from {}", grammar_path.display());
    let context = NautilusContext::from_file(10, grammar_path.to_str().unwrap())
        .expect("Failed to load grammar");
    let context_ref = Box::leak(Box::new(context));

    println!("Scanning inputs from {}", input_dir.display());
    fs::create_dir_all(output_dir).expect("Failed to create output directory");

    visit_dirs(input_dir, output_dir, context_ref);
}

fn visit_dirs(dir: &Path, output_base: &Path, context: &NautilusContext) {
    if dir.is_dir() {
        for entry in fs::read_dir(dir).expect("Failed to read directory") {
            let entry = entry.expect("Failed to read entry");
            let path = entry.path();
            if path.is_dir() {
                let dir_name = path.file_name().unwrap();
                let new_output_dir = output_base.join(dir_name);
                fs::create_dir_all(&new_output_dir).expect("Failed to create subdirectory");
                visit_dirs(&path, &new_output_dir, context);
            } else {
                // Ignore metadata, hidden files, and internal AFL files
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.starts_with('.')
                        || file_name.ends_with(".metadata")
                        || file_name == "is_main_node"
                    {
                        continue;
                    }
                }
                process_file(&path, output_base, context);
            }
        }
    }
}

fn process_file(path: &Path, output_dir: &Path, context: &NautilusContext) {
    // Expect the file to be a valid serialized Input (JSON/Postcard) or fail.
    // We rely on Input::from_file to match how it was saved.
    let input = match NautilusInput::from_file(path) {
        Ok(i) => i,
        Err(e) => {
            eprintln!(
                "Warning: Failed to deserialize {} as Input (JSON/Postcard): {}. Skipping.",
                path.display(),
                e
            );
            return;
        }
    };

    let mut unparsed = Vec::new();
    input.unparse(context, &mut unparsed);

    let file_name = path.file_name().unwrap();
    let output_path = output_dir.join(file_name);

    fs::write(&output_path, &unparsed).expect("Failed to write output file");
    println!("Processed {}", path.display());
}
