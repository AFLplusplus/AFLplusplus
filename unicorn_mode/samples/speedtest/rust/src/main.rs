extern crate capstone;
extern crate libc;

use core::cell::Cell;
use std::{
    env,
    fs::File,
    io::{self, Read},
    path::PathBuf,
    process::abort,
    str,
};

use unicornafl::unicorn_engine::RegisterX86;
use unicornafl::{
    afl_fuzz_custom,
    executor::{UnicornAflExecutorHook, UnicornFuzzData},
    unicorn_engine::{uc_error, Arch, Mode, Prot, Unicorn},
};

const BINARY: &str = "../target";

// Memory map for the code to be tested
// Arbitrary address where code to test will be loaded
const BASE_ADDRESS: u64 = 0x0;
// Max size for the code (64kb)
const CODE_SIZE_MAX: u64 = 0x00010000;
// Location where the input will be placed (make sure the uclated program knows this somehow, too ;) )
const INPUT_ADDRESS: u64 = 0x00100000;
// Maximum size for our input
const INPUT_MAX: u64 = 0x00100000;
// Where our pseudo-heap is at
const HEAP_ADDRESS: u64 = 0x00200000;
// Maximum allowable size for the heap
const HEAP_SIZE_MAX: u64 = 0x000F0000;
// Address of the stack (Some random address again)
const STACK_ADDRESS: u64 = 0x00400000;
// Size of the stack (arbitrarily chosen, just make it big enough)
const STACK_SIZE: u64 = 0x000F0000;

fn read_file(filename: &str) -> Result<Vec<u8>, io::Error> {
    let mut f = File::open(filename)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Our location parser
fn parse_locs(loc_name: &str) -> Result<Vec<u64>, io::Error> {
    let contents = &read_file(&format!("../target.offsets.{}", loc_name))?;
    //println!("Read: {:?}", contents);
    Ok(str_from_u8_unchecked(contents)
        .split('\n')
        .map(|x| {
            //println!("Trying to convert {}", &x[2..]);
            let result = u64::from_str_radix(&x[2..], 16);
            result.unwrap()
        })
        .collect())
}

// find null terminated string in vec
pub fn str_from_u8_unchecked(utf8_src: &[u8]) -> &str {
    let nul_range_end = utf8_src
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len());
    unsafe { str::from_utf8_unchecked(&utf8_src[0..nul_range_end]) }
}

fn align(size: u64) -> u64 {
    const ALIGNMENT: u64 = 0x1000;
    if size % ALIGNMENT == 0 {
        size
    } else {
        ((size / ALIGNMENT) + 1) * ALIGNMENT
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        println!("Missing parameter <uclation_input> (@@ for AFL)");
        return;
    }
    let input_file = &args[1];
    println!("The input testcase is set to {}", input_file);
    fuzz(input_file).unwrap();
}

struct FuzzCB;

impl<'a, D> UnicornAflExecutorHook<'a, D> for FuzzCB {
    fn place_input(
        &mut self,
        uc: &mut Unicorn<'a, unicornafl::executor::UnicornFuzzData<D>>,
        afl_input: &[u8],
        _persistent_round: u64,
    ) -> bool {
        // apply constraints to the mutated input
        if afl_input.len() > INPUT_MAX as usize {
            //println!("Skipping testcase with leng {}", afl_input.len());
            return false;
        }

        uc.mem_write(INPUT_ADDRESS, afl_input).unwrap();
        uc.mem_write(INPUT_ADDRESS + afl_input.len() as u64, b"\0")
            .unwrap();
        true
    }

    fn validate_crash(
        &mut self,
        _uc: &mut Unicorn<'a, unicornafl::executor::UnicornFuzzData<D>>,
        unicorn_result: Result<(), uc_error>,
        _input: &[u8],
        _persistent_round: u64,
    ) -> bool {
        unicorn_result.is_err()
    }
}

fn fuzz(input_file: &str) -> Result<(), uc_error> {
    let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, UnicornFuzzData::default())?;

    let binary =
        read_file(BINARY).unwrap_or_else(|_| panic!("Could not read modem image: {}", BINARY));
    let _aligned_binary_size = align(binary.len() as u64);
    // Apply constraints to the mutated input
    if binary.len() as u64 > CODE_SIZE_MAX {
        println!("Binary code is too large (> {} bytes)", CODE_SIZE_MAX);
    }

    // Write the binary to its place in mem
    uc.mem_map(BASE_ADDRESS, CODE_SIZE_MAX, Prot::ALL)?;
    uc.mem_write(BASE_ADDRESS, &binary)?;

    // Set the program counter to the start of the code
    let main_locs = parse_locs("main").unwrap();
    //println!("Entry Point: {:x}", main_locs[0]);
    uc.reg_write(RegisterX86::RIP, main_locs[0])?;

    // Setup the stack.
    uc.mem_map(STACK_ADDRESS, STACK_SIZE, Prot::READ | Prot::WRITE)?;
    // Setup the stack pointer, but allocate two pointers for the pointers to input.
    uc.reg_write(RegisterX86::RSP, STACK_ADDRESS + STACK_SIZE - 16)?;

    // Setup our input space, and push the pointer to it in the function params
    uc.mem_map(INPUT_ADDRESS, INPUT_MAX, Prot::ALL)?;
    // We have argc = 2
    uc.reg_write(RegisterX86::RDI, 2)?;
    // RSI points to our little 2 QWORD space at the beginning of the stack...
    uc.reg_write(RegisterX86::RSI, STACK_ADDRESS + STACK_SIZE - 16)?;
    // ... which points to the Input. Write the ptr to mem in little endian.
    uc.mem_write(
        STACK_ADDRESS + STACK_SIZE - 16,
        &(INPUT_ADDRESS as u32).to_le_bytes(),
    )?;

    let already_allocated = Cell::new(false);

    let already_allocated_malloc = already_allocated.clone();
    // We use a very simple malloc/free stub here,
    // that only works for exactly one allocation at a time.
    let hook_malloc = move |uc: &mut Unicorn<'_, _>, addr: u64, size: u32| {
        if already_allocated_malloc.get() {
            println!("Double malloc, not supported right now!");
            abort();
        }
        // read the first param
        let malloc_size = uc.reg_read(RegisterX86::RDI).unwrap();
        if malloc_size > HEAP_SIZE_MAX {
            println!(
                "Tried to allocate {} bytes, but we may only allocate up to {}",
                malloc_size, HEAP_SIZE_MAX
            );
            abort();
        }
        uc.reg_write(RegisterX86::RAX, HEAP_ADDRESS).unwrap();
        uc.reg_write(RegisterX86::RIP, addr + size as u64).unwrap();
        already_allocated_malloc.set(true);
    };

    let already_allocated_free = already_allocated;
    // No real free, just set the "used"-flag to false.
    let hook_free = move |uc: &mut Unicorn<'_, _>, addr, size| {
        if already_allocated_free.get() {
            println!("Double free detected. Real bug?");
            abort();
        }
        // read the first param
        let free_ptr = uc.reg_read(RegisterX86::RDI).unwrap();
        if free_ptr != HEAP_ADDRESS {
            println!(
                "Tried to free wrong mem region {:x} at code loc {:x}",
                free_ptr, addr
            );
            abort();
        }
        uc.reg_write(RegisterX86::RIP, addr + size as u64).unwrap();
        already_allocated_free.set(false);
    };

    /*
        BEGIN FUNCTION HOOKS
    */

    // This is a fancy print function that we're just going to skip for fuzzing.
    let hook_magicfn = move |uc: &mut Unicorn<'_, _>, addr, size| {
        uc.reg_write(RegisterX86::RIP, addr + size as u64).unwrap();
    };

    for addr in parse_locs("malloc").unwrap() {
        //hook!(addr, hook_malloc, "malloc");
        uc.add_code_hook(addr, addr, Box::new(hook_malloc.clone()))?;
    }

    for addr in parse_locs("free").unwrap() {
        uc.add_code_hook(addr, addr, Box::new(hook_free.clone()))?;
    }

    for addr in parse_locs("magicfn").unwrap() {
        uc.add_code_hook(addr, addr, Box::new(hook_magicfn))?;
    }

    let end_addrs = parse_locs("main_ends").unwrap();

    let ret = afl_fuzz_custom(
        uc,
        Some(PathBuf::from(input_file)),
        FuzzCB,
        end_addrs,
        false,
        Some(1000),
    );

    match ret {
        Ok(_) => {}
        Err(e) => panic!("found non-ok unicorn exit: {:?}", e),
    }

    Ok(())
}
