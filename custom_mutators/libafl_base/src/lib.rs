#![cfg(unix)]

use std::{cell::RefCell, collections::HashMap, ffi::CStr, num::NonZeroUsize};

#[cfg(feature = "mutator")]
use custom_mutator::{CustomMutator, export_mutator};
use custom_mutator::{afl_state, queue_entry};
#[cfg(feature = "mutator")]
use libafl::corpus::NopCorpus;
use libafl::{
    Error,
    corpus::{CachedOnDiskCorpus, Corpus, CorpusId, Testcase},
    inputs::{
        BytesInput, BytesInputConverter, FromTargetBytesConverter, Input, ToTargetBytesConverter,
    },
    prelude::*,
};
use libafl_bolts::AsSlice;
#[cfg(feature = "mutator")]
use libafl_bolts::rands::StdRand;
#[cfg(feature = "mutator")]
use libafl_bolts::tuples::Merge;
use lru::LruCache;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A simplified `AflCorpus` that strictly wraps the AFL queue without a shadow corpus.
#[derive(Debug)]
pub struct AflCorpus<I = BytesInput, D = BytesInputConverter> {
    cache: RefCell<LruCache<CorpusId, Box<RefCell<Testcase<I>>>>>,
    current: Option<CorpusId>,
    target_byte_converter: RefCell<D>,
    afl: &'static afl_state,
    bytes_to_id: RefCell<HashMap<Vec<u8>, CorpusId>>,
}

impl<I, D> AflCorpus<I, D>
where
    I: Input,
    D: FromTargetBytesConverter<I, ()> + ToTargetBytesConverter<I, ()>,
{
    /// Creates a new [`AflCorpus`].
    ///
    /// # Errors
    ///
    /// Returns an error if the corpus cannot be initialized.
    pub fn new(afl: &'static afl_state, cache_max_len: NonZeroUsize) -> Result<Self, Error>
    where
        D: Default,
    {
        Self::with_converter(afl, cache_max_len, D::default())
    }

    /// Creates a new [`AflCorpus`] with a custom converter.
    ///
    /// # Errors
    ///
    /// Returns an error if the corpus cannot be initialized.
    pub fn with_converter(
        afl: &'static afl_state,
        cache_max_len: NonZeroUsize,
        converter: D,
    ) -> Result<Self, Error> {
        Ok(Self {
            cache: RefCell::new(LruCache::new(cache_max_len)),
            current: None,
            target_byte_converter: RefCell::new(converter),
            afl,
            bytes_to_id: RefCell::new(HashMap::new()),
        })
    }

    #[inline]
    pub fn target_byte_converter(&self) -> &RefCell<D> {
        &self.target_byte_converter
    }

    pub fn queue_cur_ptr(&self) -> *const std::ffi::c_void {
        self.afl.queue_cur.cast()
    }

    /// Gets the current input from the AFL queue, if available.
    ///
    /// # Errors
    ///
    /// Returns an error if the input cannot be retrieved or parsed.
    pub fn current_input(&self) -> Result<Option<I>, Error>
    where
        I: Input + Clone,
    {
        let queue_cur = self.afl.queue_cur;
        if queue_cur.is_null() {
            return Ok(None);
        }

        let raw_filename = unsafe { (*queue_cur).fname };
        let c_filename = unsafe { CStr::from_ptr(raw_filename as *const std::ffi::c_char) };
        let filename_str = c_filename.to_string_lossy();

        let id_str = if let Some(stripped) = filename_str.strip_prefix("id:") {
            stripped.split(',').next().unwrap_or(stripped)
        } else {
            return Ok(None);
        };

        if let Ok(id_val) = id_str.parse::<usize>() {
            let id = CorpusId::from(id_val);
            if let Ok(Some(input)) = Corpus::get(self, id).map(|tc| tc.borrow().input().clone()) {
                return Ok(Some(input));
            }
        }

        log::warn!("AflCorpus: Failed to parse ID from filename: {filename_str}");
        Ok(None)
    }

    /// Callback for when a new entry is added to the queue.
    ///
    /// # Errors
    ///
    /// Returns an error if handling the new entry fails.
    pub fn on_queue_new_entry(
        &mut self,
        _filename_new_queue: &std::path::Path,
        input: Option<I>,
    ) -> Result<bool, Error>
    where
        I: Clone + Input,
    {
        if let Some(input) = input {
            let mut converter = self.target_byte_converter.borrow_mut();
            let _bytes = converter.convert_to_target_bytes(&mut (), &input);
        }
        Ok(false)
    }
}

impl<I, D> AflCorpus<I, D>
where
    I: Input,
    D: FromTargetBytesConverter<I, ()> + ToTargetBytesConverter<I, ()>,
{
    /// Check if the testcase is in the cache.
    #[inline]
    pub fn get_from_cache(&self, id: CorpusId) -> Option<&RefCell<Testcase<I>>> {
        let cache_ptr = self.cache.as_ptr();
        unsafe { (*cache_ptr).get(&id).map(|entry| &**entry) }
    }

    /// Add a testcase to the cache.
    ///
    /// # Panics
    ///
    /// Panics if the testcase was not correctly added to the cache.
    pub fn add_to_cache(&self, id: CorpusId, testcase: Testcase<I>) -> &RefCell<Testcase<I>> {
        let cache_ptr = self.cache.as_ptr();
        unsafe {
            (*cache_ptr).put(id, Box::new(RefCell::new(testcase)));
            (*cache_ptr).get(&id).unwrap()
        }
    }

    /// Load a testcase from the AFL queue (disk) without checking cache/shadow.
    ///
    /// # Errors
    ///
    /// Returns an error if the file is not found, cannot be read, or conversion fails.
    ///
    /// # Panics
    ///
    /// Panics if the queue entry pointer is null.
    pub fn load_from_afl(&self, id: CorpusId) -> Result<Testcase<I>, Error> {
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
        let fname_cstr = unsafe { CStr::from_ptr(entry.fname as *const std::ffi::c_char) };
        let filename_str = fname_cstr.to_str().unwrap();
        let fname = std::path::Path::new(filename_str)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        let path = std::path::Path::new(filename_str);
        if !path.exists() {
            return Err(Error::illegal_state(format!(
                "File not found: {}",
                path.display()
            )));
        }
        let bytes =
            std::fs::read(path).map_err(|e| Error::unknown(format!("Failed to read file: {e}")))?;

        let mut converter = self.target_byte_converter.borrow_mut();
        let input = converter.convert_from_target_bytes(&mut (), &bytes)?;

        Ok(Testcase::with_filename(input, fname))
    }

    /// Helper to get the filename for a given `CorpusId` from the AFL queue.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID is not found.
    ///
    /// # Panics
    ///
    /// Panics if the queue entry pointer is null.
    pub fn get_filename_for_id(&self, id: CorpusId) -> Result<String, Error> {
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
        let fname_cstr = unsafe { CStr::from_ptr(entry.fname as *const std::ffi::c_char) };
        let filename_str = fname_cstr.to_str().unwrap();
        let fname = std::path::Path::new(filename_str)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        Ok(fname)
    }
}

impl<I, D> Clone for AflCorpus<I, D>
where
    I: Clone + Input,
    D: Clone + FromTargetBytesConverter<I, ()> + ToTargetBytesConverter<I, ()>,
{
    fn clone(&self) -> Self {
        let cap = self.cache.borrow().cap();
        Self {
            cache: RefCell::new(LruCache::new(cap)),
            current: None,
            target_byte_converter: RefCell::new(self.target_byte_converter.borrow().clone()),
            afl: self.afl,
            bytes_to_id: RefCell::new(HashMap::new()),
        }
    }
}

impl<I, D> Serialize for AflCorpus<I, D>
where
    I: Input,
    D: FromTargetBytesConverter<I, ()> + ToTargetBytesConverter<I, ()>,
{
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        unimplemented!();
    }
}

impl<'de, I, D> Deserialize<'de> for AflCorpus<I, D>
where
    I: Input,
    D: FromTargetBytesConverter<I, ()> + ToTargetBytesConverter<I, ()>,
{
    fn deserialize<D_>(_target_byte_converter: D_) -> Result<Self, D_::Error>
    where
        D_: Deserializer<'de>,
    {
        unimplemented!();
    }
}

impl<I, D> Corpus<I> for AflCorpus<I, D>
where
    I: Input + Clone,
    D: FromTargetBytesConverter<I, ()> + ToTargetBytesConverter<I, ()>,
{
    #[inline]
    fn count(&self) -> usize {
        self.afl.queued_items as usize
    }

    fn count_disabled(&self) -> usize {
        0
    }

    #[inline]
    fn count_all(&self) -> usize {
        self.afl.queued_items as usize
    }

    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        let bytes = if let Some(input) = testcase.input() {
            let mut converter = self.target_byte_converter.borrow_mut();
            let bytes = converter.convert_to_target_bytes(&mut (), input);
            Some(bytes.as_slice().to_vec())
        } else {
            None
        };

        // We assume the ID is what AFL thinks it is (count).
        let id = CorpusId::from(self.afl.queued_items as usize);

        if let Some(b) = bytes {
            self.bytes_to_id.borrow_mut().insert(b.clone(), id);
        }
        self.add_to_cache(id, testcase);
        Ok(id)
    }

    #[inline]
    fn add_disabled(&mut self, _testcase: Testcase<I>) -> Result<CorpusId, Error> {
        Ok(CorpusId::from(0usize))
    }

    #[inline]
    fn replace(&mut self, _id: CorpusId, _testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        Err(Error::unsupported("Cannot replace in simple AflCorpus"))
    }

    fn remove(&mut self, _id: CorpusId) -> Result<Testcase<I>, Error> {
        Err(Error::unsupported("Cannot remove from simple AflCorpus"))
    }

    #[inline]
    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        if let Some(entry) = self.get_from_cache(id) {
            return Ok(entry);
        }

        let testcase = self.load_from_afl(id)?;
        Ok(self.add_to_cache(id, testcase))
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
        if id.0 + 1 < self.afl.queued_items as usize {
            Some(CorpusId::from(id.0 + 1))
        } else {
            None
        }
    }

    #[inline]
    fn peek_free_id(&self) -> CorpusId {
        CorpusId::from(self.afl.queued_items as usize)
    }

    #[inline]
    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        if id.0 > 0 {
            Some(CorpusId::from(id.0 - 1))
        } else {
            None
        }
    }

    #[inline]
    fn first(&self) -> Option<CorpusId> {
        if self.afl.queued_items > 0 {
            Some(CorpusId::from(0usize))
        } else {
            None
        }
    }

    #[inline]
    fn last(&self) -> Option<CorpusId> {
        if self.afl.queued_items > 0 {
            Some(CorpusId::from(self.afl.queued_items as usize - 1))
        } else {
            None
        }
    }

    #[inline]
    fn nth(&self, nth: usize) -> CorpusId {
        CorpusId::from(nth)
    }

    #[inline]
    fn nth_from_all(&self, nth: usize) -> CorpusId {
        CorpusId::from(nth)
    }

    #[inline]
    fn load_input_into(&self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        let Some(filename) = testcase.filename() else {
            return Err(Error::illegal_argument("No filename to load input from"));
        };

        let path = std::path::Path::new(filename);
        if !path.exists() {
            return Err(Error::illegal_state(format!(
                "File not found: {}",
                path.display()
            )));
        }

        let bytes = std::fs::read(path)?;
        let mut converter = self.target_byte_converter.borrow_mut();
        let input = converter.convert_from_target_bytes(&mut (), &bytes)?;
        testcase.set_input(input);
        Ok(())
    }

    #[inline]
    fn store_input_from(&self, _testcase: &Testcase<I>) -> Result<(), Error> {
        Ok(())
    }
}

/// `AflCustomInputCorpus` backing the corpus with a shadow directory and optional custom input type.
#[derive(Debug)]
pub struct AflCustomInputCorpus<I = BytesInput, D = BytesInputConverter> {
    base: AflCorpus<I, D>,
    shadow: CachedOnDiskCorpus<I>,
    shadow_dir: std::path::PathBuf,
}

impl<I, D> AflCustomInputCorpus<I, D>
where
    I: Input,
    D: FromTargetBytesConverter<I, ()> + ToTargetBytesConverter<I, ()>,
{
    /// Creates a new [`AflCustomInputCorpus`].
    ///
    /// # Errors
    ///
    /// Returns an error if the shadow corpus cannot be created.
    pub fn new(
        afl: &'static afl_state,
        dir_path: &std::path::Path,
        cache_max_len: NonZeroUsize,
        converter: D,
    ) -> Result<Self, Error> {
        let base = AflCorpus::with_converter(afl, cache_max_len, converter)?;
        let shadow = CachedOnDiskCorpus::new(dir_path, cache_max_len.get())?;

        Ok(Self {
            base,
            shadow,
            shadow_dir: dir_path.to_path_buf(),
        })
    }

    #[inline]
    pub fn target_byte_converter(&self) -> &RefCell<D> {
        self.base.target_byte_converter()
    }

    #[inline]
    pub fn shadow_file_path(&self, filename: &str) -> Option<std::path::PathBuf> {
        Some(self.shadow_dir.join(filename))
    }

    pub fn queue_cur_ptr(&self) -> *const std::ffi::c_void {
        self.base.queue_cur_ptr()
    }

    /// Loads a testcase from the shadow corpus disk storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or deserialized.
    pub fn load_from_disk<S: Into<String>>(
        &self,
        filename: S,
    ) -> Result<Option<Testcase<I>>, Error> {
        let filename = filename.into();
        let Some(path) = self.shadow_file_path(&filename) else {
            return Ok(None);
        };

        if !path.exists() {
            return Ok(None);
        }

        let input = I::from_file(&path)?;
        let mut testcase = Testcase::new(input);
        *testcase.filename_mut() = Some(filename);
        Ok(Some(testcase))
    }

    /// Loads or adds an input from the queue, handling shadow corpus persistence.
    ///
    /// # Errors
    ///
    /// Returns an error if the input cannot be loaded, converted, or persisted.
    ///
    /// # Panics
    ///
    /// Panics if the filename cannot be extracted from the path.
    pub fn load_or_add_from_queue(
        &mut self,
        filename_new_queue_path: &std::path::Path,
        tmp_input: Option<I>,
    ) -> Result<bool, Error>
    where
        I: Clone,
    {
        let filename = filename_new_queue_path
            .file_name()
            .unwrap()
            .to_string_lossy();

        // 1. Try load from Shadow Corpus
        match self.load_from_disk(filename.as_ref()) {
            Ok(Some(mut testcase)) => {
                log::info!(
                    "AflCustomInputCorpus: Shadow file {filename} exists, loaded from shadow corpus (RESUMED)"
                );
                *testcase.filename_mut() = Some(filename.to_string());
                self.add(testcase)?;
                return Ok(true);
            }
            Ok(None) => {}
            Err(e) => {
                log::warn!(
                    "AflCustomInputCorpus: Failed to load shadow file: {e:?}. Treating as new."
                );
            }
        }

        // 2. Prepare Input
        let input = if let Some(input) = tmp_input {
            log::debug!("AflCustomInputCorpus: Adding tmp_input to corpus");
            input
        } else {
            log::debug!("AflCustomInputCorpus: No tmp_input. Attempting to load from file");
            let bytes = std::fs::read(filename_new_queue_path).map_err(|e| {
                log::error!("AflCustomInputCorpus: Failed to read queue file: {e:?}");
                Error::from(e)
            })?;
            let mut converter = self.base.target_byte_converter().borrow_mut();
            match converter.convert_from_target_bytes(&mut (), &bytes) {
                Ok(i) => i,
                Err(e) => {
                    log::warn!(
                        "AflCustomInputCorpus: Failed to parse bytes: {e:?}. Ignoring entry."
                    );
                    return Ok(false);
                }
            }
        };

        // 3. Persist to Shadow Corpus
        if let Some(shadow_path) = self.shadow_file_path(&filename) {
            if let Err(e) = input.to_file(&shadow_path) {
                log::error!("AflCustomInputCorpus: Failed to persist to shadow corpus: {e:?}");
            } else {
                log::info!(
                    "AflCustomInputCorpus: Persisted to shadow corpus: {}",
                    shadow_path.display()
                );
            }
        }

        // 4. Add to Corpus
        let mut testcase = Testcase::new(input);
        *testcase.filename_mut() = Some(filename.to_string());
        self.add(testcase)?;
        log::info!("AflCustomInputCorpus: Added {filename} to corpus");

        Ok(false)
    }

    /// Callback for when a new entry is added to the queue.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn on_queue_new_entry(
        &mut self,
        filename_new_queue: &std::path::Path,
        input: Option<I>,
    ) -> Result<bool, Error>
    where
        I: Clone,
    {
        self.load_or_add_from_queue(filename_new_queue, input)
    }

    /// Callback for when an entry is retrieved from the queue.
    ///
    /// # Errors
    ///
    /// Returns an error if loading or conversion fails.
    ///
    /// # Panics
    ///
    /// Panics if the filename cannot be extracted from the path.
    pub fn on_queue_get(
        &self,
        path: &std::path::Path,
        input_slot: &mut Option<I>,
    ) -> Result<bool, Error>
    where
        I: Input + Clone,
    {
        // Try Shadow Corpus
        let filename = path.file_name().unwrap().to_string_lossy();
        if let Ok(Some(testcase)) = self.load_from_disk(filename.as_ref()) {
            input_slot.clone_from(testcase.input());
            return Ok(true);
        }

        // Fallback: Raw
        if path.exists() {
            let bytes = std::fs::read(path)?;
            let mut converter = self.base.target_byte_converter().borrow_mut();
            let input = converter.convert_from_target_bytes(&mut (), &bytes)?;

            // Persist to Shadow Corpus
            if let Some(shadow_path) = self.shadow_file_path(&filename) {
                if let Err(e) = input.to_file(&shadow_path) {
                    log::warn!(
                        "AflCustomInputCorpus: Failed to persist to shadow corpus in on_queue_get: {e:?}"
                    );
                } else {
                    log::info!(
                        "AflCustomInputCorpus: Persisted to shadow corpus in on_queue_get: {}",
                        shadow_path.display()
                    );
                }
            }

            *input_slot = Some(input);
            return Ok(true);
        }
        Ok(false)
    }
}

impl<I, D> Clone for AflCustomInputCorpus<I, D>
where
    I: Clone + Input,
    D: Clone + Default + FromTargetBytesConverter<I, ()> + ToTargetBytesConverter<I, ()>,
{
    fn clone(&self) -> Self {
        let cap = 0; // Cap is managed by base
        Self {
            base: self.base.clone(),
            shadow: CachedOnDiskCorpus::new(&self.shadow_dir, cap).unwrap(),
            shadow_dir: self.shadow_dir.clone(),
        }
    }
}

impl<I, D> Serialize for AflCustomInputCorpus<I, D>
where
    I: Input,
    D: FromTargetBytesConverter<I, ()> + ToTargetBytesConverter<I, ()>,
{
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        unimplemented!();
    }
}

impl<'de, I, D> Deserialize<'de> for AflCustomInputCorpus<I, D>
where
    I: Input,
    D: FromTargetBytesConverter<I, ()> + ToTargetBytesConverter<I, ()>,
{
    fn deserialize<D_>(_target_byte_converter: D_) -> Result<Self, D_::Error>
    where
        D_: Deserializer<'de>,
    {
        unimplemented!();
    }
}

impl<I, D> Corpus<I> for AflCustomInputCorpus<I, D>
where
    I: Input + Clone,
    D: FromTargetBytesConverter<I, ()> + ToTargetBytesConverter<I, ()>,
{
    #[inline]
    fn get_from_all(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        self.get(id)
    }

    #[inline]
    fn count(&self) -> usize {
        let local_count = self.shadow.count();
        std::cmp::max(local_count, self.base.count())
    }

    fn count_disabled(&self) -> usize {
        self.shadow.count_disabled()
    }

    #[inline]
    fn count_all(&self) -> usize {
        let local_count = self.shadow.count_all();
        std::cmp::max(local_count, self.base.count_all())
    }

    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        self.shadow.add(testcase.clone())?;
        self.base.add(testcase)
    }

    #[inline]
    fn add_disabled(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        self.shadow.add_disabled(testcase)
    }

    #[inline]
    fn replace(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        self.shadow.replace(id, testcase)
    }

    fn remove(&mut self, id: CorpusId) -> Result<Testcase<I>, Error> {
        self.shadow.remove(id)
    }

    #[inline]
    #[allow(clippy::collapsible_if)]
    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        // 1. Check Base Cache (which is the shared cache)
        if let Some(entry) = self.base.get_from_cache(id) {
            return Ok(entry);
        }

        // 2. Try inner corpus (Shadow) by FILENAME
        if let Ok(filename) = self.base.get_filename_for_id(id) {
            if let Ok(Some(testcase)) = self.load_from_disk(&filename) {
                // Add to base cache so next time it's fast
                let entry = self.base.add_to_cache(id, testcase);
                return Ok(entry);
            }
        }

        // 3. Fallback to base (AFL)
        // This will load from AFL, convert, AND we should persist to shadow for next time.
        // We use load_from_afl directly to avoid redundant cache check in base.get()
        let testcase = self.base.load_from_afl(id)?;

        if let Some(filename) = testcase.filename().clone() {
            if let Some(shadow_dir) = self.shadow_file_path(&filename) {
                if let Some(input) = testcase.input() {
                    if let Err(e) = input.to_file(&shadow_dir) {
                        log::warn!("Failed to persist fallback input to shadow: {e:?}");
                    }
                }
            }
        }

        let entry = self.base.add_to_cache(id, testcase);
        Ok(entry)
    }

    #[inline]
    fn current(&self) -> &Option<CorpusId> {
        self.base.current()
    }

    #[inline]
    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        self.base.current_mut()
    }

    #[inline]
    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.base.next(id)
    }

    #[inline]
    fn peek_free_id(&self) -> CorpusId {
        self.base.peek_free_id()
    }

    #[inline]
    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.base.prev(id)
    }

    #[inline]
    fn first(&self) -> Option<CorpusId> {
        self.base.first()
    }

    #[inline]
    fn last(&self) -> Option<CorpusId> {
        self.base.last()
    }

    #[inline]
    fn nth(&self, nth: usize) -> CorpusId {
        self.base.nth(nth)
    }

    #[inline]
    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.base.nth_from_all(nth)
    }

    #[inline]
    fn load_input_into(&self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        // Try inner first?
        if self.shadow.load_input_into(testcase).is_ok() {
            return Ok(());
        }
        self.base.load_input_into(testcase)
    }

    #[inline]
    fn store_input_from(&self, testcase: &Testcase<I>) -> Result<(), Error> {
        self.shadow.store_input_from(testcase)
    }
}

#[cfg(feature = "mutator")]
struct LibAflBaseCustomMutator {
    state: StdState<AflCorpus, BytesInput, StdRand, NopCorpus<BytesInput>>,
    input: BytesInput,
}

#[cfg(feature = "mutator")]
impl CustomMutator for LibAflBaseCustomMutator {
    type Error = libafl::Error;

    fn init(afl: &'static afl_state, seed: u32) -> Result<Self, Self::Error> {
        let rand = StdRand::with_seed(u64::from(seed));

        let corpus = AflCorpus::new(afl, nonzero!(4096)).unwrap();
        let solutions = NopCorpus::new();
        let mut feedback = ();
        let mut objective = ();
        let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)?;

        let extras = if afl.extras.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(afl.extras, afl.extras_cnt as usize) }
        };
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
        filename_new_queue: &std::path::Path,
        _filename_orig_queue: Option<&std::path::Path>,
    ) -> Result<bool, Self::Error> {
        self.state
            .corpus_mut()
            .on_queue_new_entry(filename_new_queue, Some(self.input.clone()))
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

        // Create dummy file for possible fallback reload
        std::fs::write("id:000000", b"dummy").unwrap();

        let layout = std::alloc::Layout::new::<afl_state>();
        #[allow(clippy::cast_ptr_alignment)]
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<afl_state>();
        let afl = unsafe { &*ptr };

        let corpus = AflCorpus::new(afl, nonzero!(4096)).unwrap();
        let solutions = NopCorpus::new();
        let mut feedback = ();
        let mut objective = ();
        let mut state =
            StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();

        let dummy_input = BytesInput::new(b"dummy".to_vec());
        let mut testcase = Testcase::new(dummy_input);
        *testcase.filename_mut() = Some("id:000000".to_string());
        // Safety: We force the queued_items to 0 initially so add uses ID 0
        unsafe {
            let ptr_mut = ptr as *mut afl_state;
            (*ptr_mut).queued_items = 0;

            // Allocate a dummy queue entry to avoid null pointer derefs if fallback happens
            let layout_entry = std::alloc::Layout::new::<queue_entry>();
            let ptr_entry = std::alloc::alloc_zeroed(layout_entry).cast::<queue_entry>();

            // Allocate dummy fname "id:000000"
            let fname = std::ffi::CString::new("id:000000").unwrap();
            // We leak the string to keep it valid
            (*ptr_entry).fname = fname.into_raw() as *mut u8;

            // Allocate buffer for queue pointers (array of pointers)
            let layout_buf = std::alloc::Layout::array::<*mut queue_entry>(1).unwrap();
            let ptr_buf = std::alloc::alloc(layout_buf) as *mut *mut queue_entry;
            *ptr_buf = ptr_entry;

            (*ptr_mut).queue_buf = ptr_buf;
        }

        state.corpus_mut().add(testcase).unwrap();

        // Update queued_items to 1 so Corpus::count() returns 1
        unsafe {
            let ptr_mut = ptr as *mut afl_state;
            (*ptr_mut).queued_items = 1;
        }

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

        assert_eq!(
            mutated_bytes.as_slice(),
            mutator.input.target_bytes().as_slice()
        );

        let _ = std::fs::remove_file("id:000000");
    }
}
