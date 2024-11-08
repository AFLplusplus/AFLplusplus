#![cfg(unix)]
//! Somewhat safe and somewhat ergonomic bindings for creating [AFL++](https://github.com/AFLplusplus/AFLplusplus) [custom mutators](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/custom_mutators.md) in Rust.
//!
//! # Usage
//! AFL++ custom mutators are expected to be dynamic libraries which expose a set of symbols.
//! Check out [`CustomMutator`] to see which functions of the API are supported.
//! Then use [`export_mutator`] to export the correct symbols for your mutator.
//! In order to use the mutator, your crate needs to be a library crate and have a `crate-type` of `cdylib`.
//! Putting
//! ```yaml
//! [lib]
//! crate-type = ["cdylib"]
//! ```
//! into your `Cargo.toml` should do the trick.
//! The final executable can be found in `target/(debug|release)/your_crate_name.so`.
//! # Example
//! See [`export_mutator`] for an example.
//!
//! # On `panic`s
//! This binding is panic-safe in that it will prevent panics from unwinding into AFL++. Any panic will `abort` at the boundary between the custom mutator and AFL++.
//!
//! # Access to AFL++ internals
//! This crate has an optional feature "`afl_internals`", which gives access to AFL++'s internal state.
//! The state is passed to [`CustomMutator::init`], when the feature is activated.
//!
//! _This is completely unsafe and uses automatically generated types extracted from the AFL++ source._
use std::{fmt::Debug, path::Path};

#[cfg(feature = "afl_internals")]
#[doc(hidden)]
pub use custom_mutator_sys::afl_state;

#[allow(unused_variables)]
#[doc(hidden)]
pub trait RawCustomMutator {
    #[cfg(feature = "afl_internals")]
    fn init(afl: &'static afl_state, seed: u32) -> Self
    where
        Self: Sized;
    #[cfg(not(feature = "afl_internals"))]
    fn init(seed: u32) -> Self
    where
        Self: Sized;

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Option<&'b [u8]>;

    fn fuzz_count(&mut self, buffer: &[u8]) -> u32 {
        1
    }

    fn queue_new_entry(
        &mut self,
        filename_new_queue: &Path,
        _filename_orig_queue: Option<&Path>,
    ) -> bool {
        false
    }

    fn queue_get(&mut self, filename: &Path) -> bool {
        true
    }

    fn describe(&mut self, max_description: usize) -> Option<&str> {
        Some(default_mutator_describe::<Self>(max_description))
    }

    fn introspection(&mut self) -> Option<&str> {
        None
    }

    fn post_process<'b, 's: 'b>(&'s mut self, buffer: &'b mut [u8]) -> Option<&'b [u8]>;

    /*fn post_process(&self, buffer: &[u8], unsigned char **out_buf)-> usize;
    int afl_custom_init_trim(&self, buffer: &[u8]);
    size_t afl_custom_trim(&self, unsigned char **out_buf);
    int afl_custom_post_trim(&self, unsigned char success);
    size_t afl_custom_havoc_mutation(&self, buffer: &[u8], unsigned char **out_buf, size_t max_size);
    unsigned char afl_custom_havoc_mutation_probability(&self);*/
}

/// Wrappers for the custom mutator which provide the bridging between the C API and CustomMutator.
/// These wrappers are not intended to be used directly, rather export_mutator will use them to publish the custom mutator C API.
#[doc(hidden)]
pub mod wrappers {
    #[cfg(feature = "afl_internals")]
    use custom_mutator_sys::afl_state;

    use std::{
        any::Any,
        ffi::{c_void, CStr, OsStr},
        mem::ManuallyDrop,
        os::{raw::c_char, unix::ffi::OsStrExt},
        panic::catch_unwind,
        path::Path,
        process::abort,
        ptr::null,
        slice,
    };

    use crate::RawCustomMutator;

    /// A structure to be used as the data pointer for our custom mutator. This was used as additional storage and is kept for now in case its needed later.
    /// Also has some convenience functions for FFI conversions (from and to ptr) and tries to make misuse hard (see [`FFIContext::from`]).
    struct FFIContext<M: RawCustomMutator> {
        mutator: M,
        /// buffer for storing the description returned by [`RawCustomMutator::describe`] as a CString
        description_buffer: Vec<u8>,
        /// buffer for storing the introspection returned by [`RawCustomMutator::introspect`] as a CString
        introspection_buffer: Vec<u8>,
    }

    impl<M: RawCustomMutator> FFIContext<M> {
        fn from(ptr: *mut c_void) -> ManuallyDrop<Box<Self>> {
            assert!(!ptr.is_null());
            ManuallyDrop::new(unsafe { Box::from_raw(ptr.cast::<Self>()) })
        }

        fn into_ptr(self: Box<Self>) -> *const c_void {
            Box::into_raw(self) as *const c_void
        }

        #[cfg(feature = "afl_internals")]
        fn new(afl: &'static afl_state, seed: u32) -> Box<Self> {
            Box::new(Self {
                mutator: M::init(afl, seed),
                description_buffer: Vec::new(),
                introspection_buffer: Vec::new(),
            })
        }
        #[cfg(not(feature = "afl_internals"))]
        fn new(seed: u32) -> Box<Self> {
            Box::new(Self {
                mutator: M::init(seed),
                description_buffer: Vec::new(),
                introspection_buffer: Vec::new(),
            })
        }
    }

    /// panic handler called for every panic
    fn panic_handler(method: &str, panic_info: &Box<dyn Any + Send + 'static>) -> ! {
        use std::ops::Deref;
        let cause = panic_info.downcast_ref::<String>().map_or_else(
            || {
                panic_info
                    .downcast_ref::<&str>()
                    .copied()
                    .unwrap_or("<cause unknown>")
            },
            String::deref,
        );
        eprintln!("A panic occurred at {method}: {cause}");
        abort()
    }

    /// Internal function used in the macro
    #[cfg(not(feature = "afl_internals"))]
    #[must_use]
    pub fn afl_custom_init_<M: RawCustomMutator>(seed: u32) -> *const c_void {
        match catch_unwind(|| FFIContext::<M>::new(seed).into_ptr()) {
            Ok(ret) => ret,
            Err(err) => panic_handler("afl_custom_init", &err),
        }
    }

    /// Internal function used in the macro
    #[cfg(feature = "afl_internals")]
    pub fn afl_custom_init_<M: RawCustomMutator>(
        afl: Option<&'static afl_state>,
        seed: u32,
    ) -> *const c_void {
        match catch_unwind(|| {
            let afl = afl.expect("mutator func called with NULL afl");
            FFIContext::<M>::new(afl, seed).into_ptr()
        }) {
            Ok(ret) => ret,
            Err(err) => panic_handler("afl_custom_init", &err),
        }
    }

    /// Internal function used in the macro
    /// # Safety
    ///
    /// May dereference all passed-in pointers.
    /// Should not be called manually, but will be called by `afl-fuzz`
    pub unsafe fn afl_custom_fuzz_<M: RawCustomMutator>(
        data: *mut c_void,
        buf: *mut u8,
        buf_size: usize,
        out_buf: *mut *const u8,
        add_buf: *mut u8,
        add_buf_size: usize,
        max_size: usize,
    ) -> usize {
        match catch_unwind(|| {
            let mut context = FFIContext::<M>::from(data);

            assert!(!buf.is_null(), "null buf passed to afl_custom_fuzz");
            assert!(!out_buf.is_null(), "null out_buf passed to afl_custom_fuzz");

            let buff_slice = slice::from_raw_parts_mut(buf, buf_size);
            let add_buff_slice = if add_buf.is_null() {
                None
            } else {
                Some(slice::from_raw_parts(add_buf, add_buf_size))
            };
            if let Some(buffer) = context.mutator.fuzz(buff_slice, add_buff_slice, max_size) {
                *out_buf = buffer.as_ptr();
                buffer.len()
            } else {
                // return the input buffer with 0-length to let AFL skip this mutation attempt
                *out_buf = buf;
                0
            }
        }) {
            Ok(ret) => ret,
            Err(err) => panic_handler("afl_custom_fuzz", &err),
        }
    }

    /// Internal function used in the macro
    ///
    /// # Safety
    /// Dereferences the passed-in pointers up to `buf_size` bytes.
    /// Should not be called directly.
    pub unsafe fn afl_custom_fuzz_count_<M: RawCustomMutator>(
        data: *mut c_void,
        buf: *const u8,
        buf_size: usize,
    ) -> u32 {
        match catch_unwind(|| {
            let mut context = FFIContext::<M>::from(data);
            assert!(!buf.is_null(), "null buf passed to afl_custom_fuzz");

            let buf_slice = slice::from_raw_parts(buf, buf_size);
            // see https://doc.rust-lang.org/nomicon/borrow-splitting.html
            let ctx = &mut **context;
            let mutator = &mut ctx.mutator;
            mutator.fuzz_count(buf_slice)
        }) {
            Ok(ret) => ret,
            Err(err) => panic_handler("afl_custom_fuzz_count", &err),
        }
    }

    /// Internal function used in the macro
    pub unsafe fn afl_custom_queue_new_entry_<M: RawCustomMutator>(
        data: *mut c_void,
        filename_new_queue: *const c_char,
        filename_orig_queue: *const c_char,
    ) -> bool {
        match catch_unwind(|| {
            let mut context = FFIContext::<M>::from(data);
            assert!(
                !filename_new_queue.is_null(),
                "received null filename_new_queue in afl_custom_queue_new_entry"
            );

            let filename_new_queue = Path::new(OsStr::from_bytes(
                unsafe { CStr::from_ptr(filename_new_queue) }.to_bytes(),
            ));
            let filename_orig_queue = if filename_orig_queue.is_null() {
                None
            } else {
                Some(Path::new(OsStr::from_bytes(
                    unsafe { CStr::from_ptr(filename_orig_queue) }.to_bytes(),
                )))
            };
            context
                .mutator
                .queue_new_entry(filename_new_queue, filename_orig_queue)
        }) {
            Ok(ret) => ret,
            Err(err) => panic_handler("afl_custom_queue_new_entry", &err),
        }
    }

    /// Internal function used in the macro
    ///
    /// # Safety
    /// May dereference the passed-in `data` pointer.
    /// Should not be called directly.
    pub unsafe fn afl_custom_deinit_<M: RawCustomMutator>(data: *mut c_void) {
        match catch_unwind(|| {
            // drop the context
            ManuallyDrop::into_inner(FFIContext::<M>::from(data));
        }) {
            Ok(ret) => ret,
            Err(err) => panic_handler("afl_custom_deinit", &err),
        }
    }

    /// Internal function used in the macro
    pub fn afl_custom_introspection_<M: RawCustomMutator>(data: *mut c_void) -> *const c_char {
        match catch_unwind(|| {
            let context = &mut *FFIContext::<M>::from(data);
            if let Some(res) = context.mutator.introspection() {
                let buf = &mut context.introspection_buffer;
                buf.clear();
                buf.extend_from_slice(res.as_bytes());
                buf.push(0);
                // unwrapping here, as the error case should be extremely rare
                CStr::from_bytes_with_nul(buf).unwrap().as_ptr()
            } else {
                null()
            }
        }) {
            Ok(ret) => ret,
            Err(err) => panic_handler("afl_custom_introspection", &err),
        }
    }

    /// Internal function used in the macro
    pub fn afl_custom_describe_<M: RawCustomMutator>(
        data: *mut c_void,
        max_description_len: usize,
    ) -> *const c_char {
        match catch_unwind(|| {
            let context = &mut *FFIContext::<M>::from(data);
            if let Some(res) = context.mutator.describe(max_description_len) {
                let buf = &mut context.description_buffer;
                buf.clear();
                buf.extend_from_slice(res.as_bytes());
                buf.push(0);
                // unwrapping here, as the error case should be extremely rare
                CStr::from_bytes_with_nul(buf).unwrap().as_ptr()
            } else {
                null()
            }
        }) {
            Ok(ret) => ret,
            Err(err) => panic_handler("afl_custom_describe", &err),
        }
    }

    /// Internal function used in the macro
    pub unsafe fn afl_custom_queue_get_<M: RawCustomMutator>(
        data: *mut c_void,
        filename: *const c_char,
    ) -> u8 {
        match catch_unwind(|| {
            let mut context = FFIContext::<M>::from(data);
            assert!(!filename.is_null());

            u8::from(context.mutator.queue_get(Path::new(OsStr::from_bytes(
                unsafe { CStr::from_ptr(filename) }.to_bytes(),
            ))))
        }) {
            Ok(ret) => ret,
            Err(err) => panic_handler("afl_custom_queue_get", &err),
        }
    }

    /// Internal function used in the macro
    pub unsafe fn afl_custom_post_process<M: RawCustomMutator>(
        data: *mut c_void,
        buf: *mut u8,
        buf_size: usize,
        out_buf: *mut *const u8,
    ) -> usize {
        match catch_unwind(|| {
            let mut context = FFIContext::<M>::from(data);

            assert!(!buf.is_null(), "null buf passed to afl_custom_post_process");
            assert!(
                !out_buf.is_null(),
                "null out_buf passed to afl_custom_post_process"
            );
            let buff_slice = slice::from_raw_parts_mut(buf, buf_size);
            if let Some(buffer) = context.mutator.post_process(buff_slice) {
                *out_buf = buffer.as_ptr();
                return buffer.len();
            }
            0
        }) {
            Ok(ret) => ret,
            Err(err) => panic_handler("afl_custom_post_process", &err),
        }
    }
}

/// An exported macro to defined afl_custom_init meant for insternal usage
#[cfg(feature = "afl_internals")]
#[macro_export]
macro_rules! _define_afl_custom_init {
    ($mutator_type:ty) => {
        #[no_mangle]
        pub extern "C" fn afl_custom_init(
            afl: ::std::option::Option<&'static $crate::afl_state>,
            seed: ::std::os::raw::c_uint,
        ) -> *const ::std::os::raw::c_void {
            $crate::wrappers::afl_custom_init_::<$mutator_type>(afl, seed as u32)
        }
    };
}

/// An exported macro to defined `afl_custom_init` meant for internal usage
#[cfg(not(feature = "afl_internals"))]
#[macro_export]
macro_rules! _define_afl_custom_init {
    ($mutator_type:ty) => {
        #[no_mangle]
        pub extern "C" fn afl_custom_init(
            _afl: *const ::std::os::raw::c_void,
            seed: ::std::os::raw::c_uint,
        ) -> *const ::std::os::raw::c_void {
            $crate::wrappers::afl_custom_init_::<$mutator_type>(seed as u32)
        }
    };
}

/// exports the given Mutator as a custom mutator as the C interface that AFL++ expects.
/// It is not possible to call this macro multiple times, because it would define the custom mutator symbols multiple times.
/// # Example
/// ```
/// # #[macro_use] extern crate custom_mutator;
/// # #[cfg(feature = "afl_internals")]
/// # use custom_mutator::afl_state;
/// # use custom_mutator::CustomMutator;
/// struct MyMutator;
/// impl CustomMutator for MyMutator {
///     /// ...
/// #  type Error = ();
/// #  #[cfg(feature = "afl_internals")]
/// #  fn init(_afl_state: &afl_state, _seed: u32) -> Result<Self,()> {unimplemented!()}
/// #  #[cfg(not(feature = "afl_internals"))]
/// #  fn init(_seed: u32) -> Result<Self, Self::Error> {unimplemented!()}
/// #  fn fuzz<'b,'s:'b>(&'s mut self, _buffer: &'b mut [u8], _add_buff: Option<&[u8]>, _max_size: usize) -> Result<Option<&'b [u8]>, Self::Error> {unimplemented!()}
/// }
/// export_mutator!(MyMutator);
/// ```
#[macro_export]
macro_rules! export_mutator {
    ($mutator_type:ty) => {
        $crate::_define_afl_custom_init!($mutator_type);

        #[no_mangle]
        pub unsafe extern "C" fn afl_custom_fuzz_count(
            data: *mut ::std::os::raw::c_void,
            buf: *const u8,
            buf_size: usize,
        ) -> u32 {
            $crate::wrappers::afl_custom_fuzz_count_::<$mutator_type>(data, buf, buf_size)
        }

        #[no_mangle]
        pub unsafe extern "C" fn afl_custom_fuzz(
            data: *mut ::std::os::raw::c_void,
            buf: *mut u8,
            buf_size: usize,
            out_buf: *mut *const u8,
            add_buf: *mut u8,
            add_buf_size: usize,
            max_size: usize,
        ) -> usize {
            $crate::wrappers::afl_custom_fuzz_::<$mutator_type>(
                data,
                buf,
                buf_size,
                out_buf,
                add_buf,
                add_buf_size,
                max_size,
            )
        }

        #[no_mangle]
        pub unsafe extern "C" fn afl_custom_queue_new_entry(
            data: *mut ::std::os::raw::c_void,
            filename_new_queue: *const ::std::os::raw::c_char,
            filename_orig_queue: *const ::std::os::raw::c_char,
        ) -> bool {
            $crate::wrappers::afl_custom_queue_new_entry_::<$mutator_type>(
                data,
                filename_new_queue,
                filename_orig_queue,
            )
        }

        #[no_mangle]
        pub unsafe extern "C" fn afl_custom_queue_get(
            data: *mut ::std::os::raw::c_void,
            filename: *const ::std::os::raw::c_char,
        ) -> u8 {
            $crate::wrappers::afl_custom_queue_get_::<$mutator_type>(data, filename)
        }

        #[no_mangle]
        pub extern "C" fn afl_custom_introspection(
            data: *mut ::std::os::raw::c_void,
        ) -> *const ::std::os::raw::c_char {
            $crate::wrappers::afl_custom_introspection_::<$mutator_type>(data)
        }

        #[no_mangle]
        pub extern "C" fn afl_custom_describe(
            data: *mut ::std::os::raw::c_void,
            max_description_len: usize,
        ) -> *const ::std::os::raw::c_char {
            $crate::wrappers::afl_custom_describe_::<$mutator_type>(data, max_description_len)
        }

        #[no_mangle]
        pub unsafe extern "C" fn afl_custom_deinit(data: *mut ::std::os::raw::c_void) {
            $crate::wrappers::afl_custom_deinit_::<$mutator_type>(data)
        }

        #[no_mangle]
        pub unsafe extern "C" fn afl_custom_post_process(
            data: *mut ::std::os::raw::c_void,
            buf: *mut u8,
            buf_size: usize,
            out_buf: *mut *const u8,
        ) -> usize {
            $crate::wrappers::afl_custom_post_process::<$mutator_type>(data, buf, buf_size, out_buf)
        }
    };
}

#[cfg(test)]
/// this sanity test is supposed to just find out whether an empty mutator being exported by the macro compiles
mod sanity_test {
    #[cfg(feature = "afl_internals")]
    use super::afl_state;

    use super::{export_mutator, RawCustomMutator};

    struct ExampleMutator;

    impl RawCustomMutator for ExampleMutator {
        #[cfg(feature = "afl_internals")]
        fn init(_afl: &afl_state, _seed: u32) -> Self {
            unimplemented!()
        }

        #[cfg(not(feature = "afl_internals"))]
        fn init(_seed: u32) -> Self {
            unimplemented!()
        }

        fn fuzz<'b, 's: 'b>(
            &'s mut self,
            _buffer: &'b mut [u8],
            _add_buff: Option<&[u8]>,
            _max_size: usize,
        ) -> Option<&'b [u8]> {
            unimplemented!()
        }

        fn post_process<'b, 's: 'b>(&'s mut self, buffer: &'b mut [u8]) -> Option<&'b [u8]> {
            unimplemented!()
        }
    }

    export_mutator!(ExampleMutator);
}

/// A custom mutator.
/// [`CustomMutator::handle_error`] will be called in case any method returns an [`Result::Err`].
#[allow(unused_variables)]
#[allow(clippy::missing_errors_doc)]
pub trait CustomMutator {
    /// The error type. All methods must return the same error type.
    type Error: Debug;

    /// The method which handles errors.
    /// By default, this method will log the error to stderr if the environment variable "`AFL_CUSTOM_MUTATOR_DEBUG`" is set and non-empty.
    /// After logging the error, execution will continue on a best-effort basis.
    ///
    /// This default behaviour can be customized by implementing this method.
    fn handle_error(err: Self::Error) {
        if std::env::var("AFL_CUSTOM_MUTATOR_DEBUG")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
            eprintln!("Error in custom mutator: {err:?}");
        }
    }

    #[cfg(feature = "afl_internals")]
    fn init(afl: &'static afl_state, seed: u32) -> Result<Self, Self::Error>
    where
        Self: Sized;

    #[cfg(not(feature = "afl_internals"))]
    fn init(seed: u32) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn fuzz_count(&mut self, buffer: &[u8]) -> Result<u32, Self::Error> {
        Ok(1)
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Result<Option<&'b [u8]>, Self::Error>;

    fn queue_new_entry(
        &mut self,
        filename_new_queue: &Path,
        filename_orig_queue: Option<&Path>,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn queue_get(&mut self, filename: &Path) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn describe(&mut self, max_description: usize) -> Result<Option<&str>, Self::Error> {
        Ok(Some(default_mutator_describe::<Self>(max_description)))
    }

    fn introspection(&mut self) -> Result<Option<&str>, Self::Error> {
        Ok(None)
    }

    fn post_process<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
    ) -> Result<Option<&'b [u8]>, Self::Error> {
        Ok(Some(buffer))
    }
}

impl<M> RawCustomMutator for M
where
    M: CustomMutator,
    M::Error: Debug,
{
    #[cfg(feature = "afl_internals")]
    fn init(afl: &'static afl_state, seed: u32) -> Self
    where
        Self: Sized,
    {
        match Self::init(afl, seed) {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                panic!("Error in afl_custom_init")
            }
        }
    }

    #[cfg(not(feature = "afl_internals"))]
    fn init(seed: u32) -> Self
    where
        Self: Sized,
    {
        match Self::init(seed) {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                panic!("Error in afl_custom_init")
            }
        }
    }

    fn fuzz_count(&mut self, buffer: &[u8]) -> u32 {
        match self.fuzz_count(buffer) {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                0
            }
        }
    }

    fn fuzz<'b, 's: 'b>(
        &'s mut self,
        buffer: &'b mut [u8],
        add_buff: Option<&[u8]>,
        max_size: usize,
    ) -> Option<&'b [u8]> {
        match self.fuzz(buffer, add_buff, max_size) {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                None
            }
        }
    }

    fn queue_new_entry(
        &mut self,
        filename_new_queue: &Path,
        filename_orig_queue: Option<&Path>,
    ) -> bool {
        match self.queue_new_entry(filename_new_queue, filename_orig_queue) {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                false
            }
        }
    }

    fn queue_get(&mut self, filename: &Path) -> bool {
        match self.queue_get(filename) {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                false
            }
        }
    }

    fn describe(&mut self, max_description: usize) -> Option<&str> {
        match self.describe(max_description) {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                None
            }
        }
    }

    fn introspection(&mut self) -> Option<&str> {
        match self.introspection() {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                None
            }
        }
    }

    fn post_process<'b, 's: 'b>(&'s mut self, buffer: &'b mut [u8]) -> Option<&'b [u8]> {
        match self.post_process(buffer) {
            Ok(r) => r,
            Err(e) => {
                Self::handle_error(e);
                None
            }
        }
    }
}

/// the default value to return from [`CustomMutator::describe`].
fn default_mutator_describe<T: ?Sized>(max_len: usize) -> &'static str {
    truncate_str_unicode_safe(std::any::type_name::<T>(), max_len)
}

#[cfg(all(test, not(feature = "afl_internals")))]
mod default_mutator_describe {
    struct MyMutator;
    use super::CustomMutator;
    impl CustomMutator for MyMutator {
        type Error = ();

        fn init(_: u32) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        fn fuzz<'b, 's: 'b>(
            &'s mut self,
            _: &'b mut [u8],
            _: Option<&[u8]>,
            _: usize,
        ) -> Result<Option<&'b [u8]>, Self::Error> {
            unimplemented!()
        }
    }

    #[test]
    fn test_default_describe() {
        assert_eq!(
            MyMutator::init(0).unwrap().describe(64).unwrap().unwrap(),
            "custom_mutator::default_mutator_describe::MyMutator"
        );
    }
}

/// little helper function to truncate a `str` to a maximum of bytes while retaining unicode safety
fn truncate_str_unicode_safe(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else if let Some((last_index, _)) = s
        .char_indices()
        .take_while(|(index, _)| *index <= max_len)
        .last()
    {
        &s[..last_index]
    } else {
        ""
    }
}

#[cfg(test)]
mod truncate_test {
    use super::truncate_str_unicode_safe;

    #[test]
    fn test_truncate() {
        for (max_len, input, expected_output) in &[
            (0usize, "a", ""),
            (1, "a", "a"),
            (1, "ä", ""),
            (2, "ä", "ä"),
            (3, "äa", "äa"),
            (4, "äa", "äa"),
            (1, "👎", ""),
            (2, "👎", ""),
            (3, "👎", ""),
            (4, "👎", "👎"),
            (1, "abc", "a"),
            (2, "abc", "ab"),
        ] {
            let actual_output = truncate_str_unicode_safe(input, *max_len);
            assert_eq!(
                &actual_output, expected_output,
                "{input:#?} truncated to {max_len} bytes should be {expected_output:#?}, but is {actual_output:#?}"
            );
        }
    }
}
