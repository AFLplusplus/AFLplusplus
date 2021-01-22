extern crate capstone;
extern crate libc;

use core::cell::{Cell, RefCell};
use libc::{c_void, munmap};
use std::{
    env,
    fs::File,
    io::{self, Read},
    process::abort,
};

use unicornafl::{
    unicorn_const::{uc_error, Arch, Mode, Permission},
    utils::*,
    RegisterX86::*,
};

const BINARY: &str = &"../target";

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

macro_rules! hook {
    ($addr:expr, $func:expr) => {
        uc.add_code_hook($addr, $addr, Box::new($func))
            .expect(&format!("failed to set {} hook", stringify!($func)));
    };
    ($addr:expr, $func:expr, $opt_name:expr) => {
        uc.add_code_hook($addr, $addr, Box::new($func))
            .expect(&format!("failed to set {} hook", $opt_name));
    };
}

fn read_file(filename: &str) -> Result<Vec<u8>, io::Error> {
    let mut f = File::open(filename)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Our location parser
fn parse_locs(loc_name: &str) -> Result<Vec<u64>, io::Error> {
    let contents = &read_file(&format!("../target.offsets.{}", loc_name))?;
    str_from_u8_unchecked(&contents)
        .split("\n")
        .filter_map(|x| u64::from_str_radix(x, 16))
        .collect()
}

// find null terminated string in vec
pub unsafe fn str_from_u8_unchecked(utf8_src: &[u8]) -> &str {
    let nul_range_end = utf8_src
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len());
    ::std::str::from_utf8_unchecked(&utf8_src[0..nul_range_end])
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
    uclate(input_file).unwrap();
}

fn uclate(input_file: &str) -> Result<(), io::Error> {
    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_64, 0)?;

    let binary = read_file(BINARY).expect(&format!("Could not read modem image: {}", BINARY));
    let aligned_binary_size = align(binary.len() as u64);
    // Apply constraints to the mutated input
    if binary.len() as u64 > CODE_SIZE_MAX {
        println!("Binary code is too large (> {} bytes)", CODE_SIZE_MAX);
        Ok(())
    }

    // Write the binary to its place in mem
    uc.mem_map(
        BASE_ADDRESS,
        CODE_SIZE_MAX,
        Permission::READ | Permission::WRITE,
    )?;
    uc.mem_write(BASE_ADDR, binary);

    // Set the program counter to the start of the code
    let main_locs = parse_locs("main")?;
    uc.reg_write(RIP, main_locs[0])?;

    // Setup the stack.
    uc.mem_map(
        STACK_ADDRESS,
        STACK_SIZE as usize,
        Permission::READ | Permission::WRITE,
    )?;
    // Setup the stack pointer, but allocate two pointers for the pointers to input.
    uc.reg_write(RSP, STACK_ADDRESS + STACK_SIZE - 16)?;

    // Setup our input space, and push the pointer to it in the function params
    uc.mem_map(INPUT_ADDRESS, INPUT_MAX as usize, Permission::READ)?;
    // We have argc = 2
    uc.reg_write(RDI, 2)?;
    // RSI points to our little 2 QWORD space at the beginning of the stack...
    uc.reg_write(RSI, STACK_ADDRESS + STACK_SIZE - 16)?;
    // ... which points to the Input. Write the ptr to mem in little endian.
    uc.mem_write(
        STACK_ADDRESS + STACK_SIZE - 16,
        (INPUT_ADDRESS as u32).to_le_bytes(),
    )?;

    let already_allocated = Cell::new(false);

    let already_allocated_malloc = already_allocated.clone();
    let hook_malloc = move |mut uc: Unicorn, addr: u64, size: u32| {
        if already_allocated_malloc.get() {
            println!("Double malloc, not supported right now!");
            abort();
        }
        // read the first param
        let malloc_size = uc.reg_read(RDI).unwrap();
        if malloc_size > HEAP_SIZE_MAX {
            println!(
                "Tried to allocate {} bytes, but we may only allocate up to {}",
                malloc_size, HEAP_SIZE_MAX
            );
            abort();
        }
        uc.reg_write(RAX, HEAP_ADDRESS).unwrap();
        uc.reg_write(RIP, addr + size as u64).unwrap();
        already_allocated_malloc.set(true);
    };

    let already_allocated_free = already_allocated.clone();
    let hook_free = move |mut uc: Unicorn, addr: u64, size: u32| {
        if already_allocated_free.get() {
            println!("Double free detected. Real bug?");
            abort();
        }
        // read the first param
        let free_ptr = uc.reg_read(RDI).unwrap();
        if free_ptr != HEAP_ADDRESS {
            println!(
                "Tried to free wrong mem region {:x} at code loc {:x}",
                free_ptr, addr
            );
            abort();
        }
        uc.reg_write(RIP, addr + size as u64);
        already_allocated_free.set(false);
    };

    /*
        BEGIN FUNCTION HOOKS
    */

    let hook_magicfn =
        move |mut uc: Unicorn, addr: u64, size: u32| uc.reg_write(RIP, address + size as u64);

    for addr in parse_locs("malloc")? {
        hook!(addr, hook_malloc, "malloc");
    }

    for addr in parse_locs("free")? {
        hook!(addr, hook_free, "free");
    }

    for addr in parse_locs("magicfn")? {
        hook!(addr, hook_magicfn, "magicfn");
    }

    let place_input_callback = |mut uc: Unicorn, afl_input: &[u8], _persistent_round: i32| {
        // apply constraints to the mutated input
        if afl_input.len() > INPUT_MAX as usize {
            //println!("Skipping testcase with leng {}", afl_input.len());
            return false;
        }

        // TODO: afl_input[-1] = b'\0'
        uc.mem_write(INPUT_ADDRESS, afl_input).unwrap();
        true
    };

    let crash_validation_callback =
        |uc: Unicorn, result: uc_error, _input: &[u8], _: i32| result != uc_error::OK;

    end_addrs = parse_locs("main_ends")?;

    let ret = uc.afl_fuzz(
        input_file,
        Box::new(place_input_callback),
        &end_addrs,
        Box::new(crash_validation_callback),
        false,
        1,
    );

    match ret {
        Ok(_) => {}
        Err(e) => panic!(format!("found non-ok unicorn exit: {:?}", e)),
    }

    Ok(())
}
