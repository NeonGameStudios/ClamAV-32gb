use crate::errors::{ErrorKind, Result};
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fs::{File, OpenOptions},
    fmt,
    hash::Hash,
    io::{self, Read, Seek, SeekFrom, Write},
    mem::size_of,
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

/// Accounts parser-owned temporary blob storage against the caller's scan
/// budget. The budget must remain valid until all parser-owned blobs drop.
pub trait BlobSpoolBudget {
    /// Reserve temporary storage for a newly written blob extent.
    fn reserve(&self, bytes: u64) -> bool;

    /// Release previously reserved temporary storage.
    fn release(&self, bytes: u64);
}

static NEXT_SPOOL_ID: AtomicU64 = AtomicU64::new(0);

/// Parser-owned storage for a binary item. Stream inputs use a disk-backed
/// extent so a large object-data blob does not count as materialized memory.
pub(crate) enum ReaderBlob {
    Memory(Vec<u8>),
    Spool(ReaderSpool),
}

impl fmt::Debug for ReaderBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReaderBlob")
            .field("length", &self.len())
            .finish()
    }
}

impl ReaderBlob {
    pub(crate) fn len(&self) -> u64 {
        match self {
            ReaderBlob::Memory(data) => data.len() as u64,
            ReaderBlob::Spool(spool) => spool.length(),
        }
    }

    pub(crate) fn open_reader(&self) -> io::Result<Box<dyn Read + '_>> {
        match self {
            ReaderBlob::Memory(data) => Ok(Box::new(io::Cursor::new(data.as_slice()))),
            ReaderBlob::Spool(spool) => Ok(Box::new(spool.open_reader()?)),
        }
    }

    /// Open a nested parser reader while retaining the blob's spool policy.
    ///
    /// Object-group payloads can themselves contain binary items. Keeping
    /// the originating spool directory and budget on the nested reader makes
    /// those secondary blobs obey the same temporary-storage contract as the
    /// outer payload.
    pub(crate) fn open_reader_with_spool_options(&self) -> io::Result<Reader<'_>> {
        let (spool_directory, blob_budget) = match self {
            ReaderBlob::Memory(_) => (None, None),
            ReaderBlob::Spool(spool) => (
                spool.path.parent().map(Path::to_path_buf),
                spool.budget.clone(),
            ),
        };
        Ok(Reader::from_reader_with_options(
            self.open_reader()?,
            Reader::MAX_MATERIALIZED_BYTES,
            spool_directory,
            blob_budget,
        ))
    }
}

/// A private temporary file containing one parser-owned binary item.
pub(crate) struct ReaderSpool {
    file: File,
    path: PathBuf,
    length: u64,
    budget: Option<Rc<dyn BlobSpoolBudget>>,
}

impl ReaderSpool {
    fn create(
        directory: Option<&Path>,
        budget: Option<Rc<dyn BlobSpoolBudget>>,
    ) -> io::Result<Self> {
        let directory = directory
            .map(Path::to_path_buf)
            .unwrap_or_else(std::env::temp_dir);
        let process = std::process::id();
        for _ in 0..16 {
            let id = NEXT_SPOOL_ID.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!("onenote-parser-{}-{}.blob", process, id));
            let mut options = OpenOptions::new();
            options.write(true).read(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;

                // Object-data blobs can contain user documents. Do not let a
                // permissive process umask make a parser spool world-readable.
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        file,
                        path,
                        length: 0,
                        budget,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "unable to allocate a unique OneNote parser spool",
        ))
    }

    pub(crate) fn open_reader(&self) -> io::Result<File> {
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }

    pub(crate) fn length(&self) -> u64 {
        self.length
    }
}

impl Drop for ReaderSpool {
    fn drop(&mut self) {
        if let Some(budget) = &self.budget {
            budget.release(self.length);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

enum Input<'a> {
    Slice(&'a [u8]),
    Stream(Box<dyn Read + 'a>),
}

fn checked_reader_end(start: usize, length: usize, max: usize) -> Result<usize> {
    start.checked_add(length).ok_or_else(|| {
        ErrorKind::ResourceLimit {
            requested: usize::MAX,
            max,
        }
        .into()
    })
}

pub(crate) struct Reader<'a> {
    input: Input<'a>,
    buffer: Vec<u8>,
    cursor: usize,
    materialized_bytes: usize,
    materialization_limit: usize,
    spool_directory: Option<PathBuf>,
    blob_budget: Option<Rc<dyn BlobSpoolBudget>>,
}

impl<'a> Reader<'a> {
    pub(crate) const REFILL_SIZE: usize = 64 * 1024;
    pub(crate) const MAX_MATERIALIZED_BYTES: usize = 256 * 1024 * 1024;
    pub(crate) const MAX_COLLECTION_BYTES: usize = 64 * 1024 * 1024;
    // Keep recursive format traversal below the stack-exhaustion range while
    // allowing substantially deeper nesting than valid OneNote documents
    // normally require.
    pub(crate) const MAX_RECURSION_DEPTH: usize = 128;

    pub(crate) fn new(data: &'a [u8]) -> Reader<'a> {
        Self::new_with_materialization_limit(data, Self::MAX_MATERIALIZED_BYTES)
    }

    fn new_with_materialization_limit(
        data: &'a [u8],
        materialization_limit: usize,
    ) -> Reader<'a> {
        Reader {
            input: Input::Slice(data),
            buffer: Vec::new(),
            cursor: 0,
            materialized_bytes: 0,
            materialization_limit,
            spool_directory: None,
            blob_budget: None,
        }
    }

    pub(crate) fn from_reader<R: Read + 'a>(reader: R) -> Reader<'a> {
        Self::from_reader_with_options(reader, Self::MAX_MATERIALIZED_BYTES, None, None)
    }

    pub(crate) fn from_reader_with_options<R: Read + 'a>(
        reader: R,
        materialization_limit: usize,
        spool_directory: Option<PathBuf>,
        blob_budget: Option<Rc<dyn BlobSpoolBudget>>,
    ) -> Reader<'a> {
        Reader {
            input: Input::Stream(Box::new(reader)),
            buffer: Vec::new(),
            cursor: 0,
            materialized_bytes: 0,
            materialization_limit,
            spool_directory,
            blob_budget,
        }
    }

    #[cfg(test)]
    fn from_reader_with_materialization_limit<R: Read + 'a>(
        reader: R,
        materialization_limit: usize,
    ) -> Reader<'a> {
        Self::from_reader_with_options(reader, materialization_limit, None, None)
    }

    fn compact(&mut self) {
        if matches!(self.input, Input::Stream(_)) && self.cursor != 0 {
            self.buffer.drain(..self.cursor);
            self.cursor = 0;
        }
    }

    fn ensure(&mut self, cnt: usize) -> Result<()> {
        if cnt == 0 {
            return Ok(());
        }

        if matches!(self.input, Input::Stream(_)) && cnt > Self::REFILL_SIZE {
            return Err(ErrorKind::ResourceLimit {
                requested: cnt,
                max: Self::REFILL_SIZE,
            }
            .into());
        }

        if let Input::Slice(data) = &self.input {
            if data.len() < cnt {
                return Err(ErrorKind::UnexpectedEof.into());
            }
            return Ok(());
        }

        if cnt > self.materialization_limit {
            return Err(ErrorKind::ResourceLimit {
                requested: cnt,
                max: self.materialization_limit,
            }
            .into());
        }

        self.compact();
        while self.buffer.len().saturating_sub(self.cursor) < cnt {
            let available = self.buffer.len().saturating_sub(self.cursor);
            let requested = (cnt - available).min(Self::REFILL_SIZE);
            let start = self.buffer.len();
            let end = checked_reader_end(start, requested, self.materialization_limit)?;
            self.buffer
                .try_reserve(requested)
                .map_err(|_| ErrorKind::AllocationFailed {
                    requested: cnt,
                })?;
            self.buffer.resize(end, 0);
            let read = match &mut self.input {
                Input::Stream(reader) => loop {
                    match reader.read(&mut self.buffer[start..]) {
                        Ok(read) => break read,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error.into()),
                    }
                },
                Input::Slice(_) => unreachable!(),
            };
            if read == 0 {
                self.buffer.truncate(start);
                return Err(ErrorKind::UnexpectedEof.into());
            }
            let end = checked_reader_end(start, read, self.materialization_limit)?;
            self.buffer.truncate(end);
        }

        Ok(())
    }

    pub(crate) fn read(&mut self, cnt: usize) -> Result<&[u8]> {
        self.ensure(cnt)?;

        match &mut self.input {
            Input::Slice(data) => {
                let (head, tail) = data.split_at(cnt);
                *data = tail;
                Ok(head)
            }
            Input::Stream(_) => {
                let start = self.cursor;
                let end = checked_reader_end(start, cnt, self.materialization_limit)?;
                self.cursor = end;
                Ok(&self.buffer[start..end])
            }
        }
    }

    pub(crate) fn read_vec(&mut self, cnt: usize) -> Result<Vec<u8>> {
        let requested = self
            .materialized_bytes
            .checked_add(cnt)
            .ok_or(ErrorKind::ResourceLimit {
                requested: usize::MAX,
                max: self.materialization_limit,
            })?;
        if cnt > Self::MAX_MATERIALIZED_BYTES || requested > self.materialization_limit {
            return Err(ErrorKind::ResourceLimit {
                requested,
                max: self.materialization_limit.min(Self::MAX_MATERIALIZED_BYTES),
            }
            .into());
        }
        if cnt == 0 {
            return Ok(Vec::new());
        }

        if matches!(self.input, Input::Slice(_)) {
            let data = {
                let source = self.read(cnt)?;
                let mut data = Vec::new();
                data.try_reserve_exact(cnt).map_err(|_| {
                    ErrorKind::AllocationFailed { requested: cnt }
                })?;
                data.extend_from_slice(source);
                data
            };
            self.materialized_bytes = requested;
            return Ok(data);
        }

        let mut data = Vec::new();
        while data.len() < cnt {
            let read_len = (cnt - data.len()).min(Self::REFILL_SIZE);
            data.try_reserve_exact(read_len).map_err(|_| {
                ErrorKind::AllocationFailed { requested: cnt }
            })?;
            let bytes = self.read(read_len)?;
            data.extend_from_slice(bytes);
        }
        self.materialized_bytes = requested;
        Ok(data)
    }

    pub(crate) fn read_vec_u64(&mut self, cnt: u64) -> Result<Vec<u8>> {
        let cnt = usize::try_from(cnt).map_err(|_| ErrorKind::ResourceLimit {
            requested: usize::MAX,
            max: self.materialization_limit.min(Self::MAX_MATERIALIZED_BYTES),
        })?;
        self.read_vec(cnt)
    }

    /// Read a binary item without materializing a stream-backed payload in
    /// memory. Slice inputs retain the historical bounded `Vec` behavior;
    /// sequential inputs are copied to a private temporary file in refill
    /// sized chunks.
    pub(crate) fn read_blob(&mut self, cnt: u64) -> Result<ReaderBlob> {
        if matches!(self.input, Input::Slice(_)) {
            return self.read_vec_u64(cnt).map(ReaderBlob::Memory);
        }
        if cnt == 0 {
            // Empty stream-backed blobs have no payload to spill. Avoid
            // creating a temporary file merely to represent zero bytes.
            return Ok(ReaderBlob::Memory(Vec::new()));
        }

        let mut spool = ReaderSpool::create(self.spool_directory.as_deref(), self.blob_budget.clone())?;
        let mut remaining = cnt;
        while remaining != 0 {
            let requested = remaining.min(Self::REFILL_SIZE as u64) as usize;
            let bytes = self.read(requested)?;
            let written = u64::try_from(bytes.len()).map_err(|_| ErrorKind::TemporaryLimit {
                requested: u64::MAX,
            })?;
            let new_length = spool
                .length
                .checked_add(written)
                .ok_or(ErrorKind::TemporaryLimit {
                    requested: u64::MAX,
                })?;
            if let Some(budget) = &spool.budget {
                if !budget.reserve(written) {
                    return Err(ErrorKind::TemporaryLimit {
                        requested: new_length,
                    }
                    .into());
                }
            }
            if let Err(error) = spool.file.write_all(bytes) {
                if let Some(budget) = &spool.budget {
                    budget.release(written);
                }
                return Err(error.into());
            }
            spool.length = new_length;
            remaining -= bytes.len() as u64;
        }

        Ok(ReaderBlob::Spool(spool))
    }

    /// Check a count before using it to size a parser-owned collection.
    pub(crate) fn checked_collection_count<T>(&self, count: u64) -> Result<usize> {
        let count: usize = count
            .try_into()
            .map_err(|_| ErrorKind::CollectionLimit {
                requested: usize::MAX,
                max: self.collection_limit(),
            })?;
        let requested = count
            .checked_mul(size_of::<T>())
            .ok_or(ErrorKind::CollectionLimit {
                requested: usize::MAX,
                max: self.collection_limit(),
            })?;
        let max = self.collection_limit();
        if requested > max {
            return Err(ErrorKind::CollectionLimit { requested, max }.into());
        }

        Ok(count)
    }

    pub(crate) fn reserve_vec<T>(&self, values: &mut Vec<T>, count: usize) -> Result<()> {
        reserve_collection(values, count)
    }

    pub(crate) fn reserve_next_vec<T>(&self, values: &mut Vec<T>) -> Result<()> {
        let next = values.len().checked_add(1).ok_or(ErrorKind::CollectionLimit {
            requested: usize::MAX,
            max: self.collection_limit(),
        })?;
        self.checked_collection_count::<T>(next as u64)?;
        self.reserve_vec(values, 1)
    }

    pub(crate) fn reserve_map<K: Eq + Hash, V>(
        &self,
        values: &mut HashMap<K, V>,
        count: usize,
    ) -> Result<()> {
        reserve_collection_map(values, count)
    }

    pub(crate) fn reserve_next_map<K: Eq + Hash, V>(
        &self,
        values: &mut HashMap<K, V>,
    ) -> Result<()> {
        let next = values.len().checked_add(1).ok_or(ErrorKind::CollectionLimit {
            requested: usize::MAX,
            max: self.collection_limit(),
        })?;
        self.checked_collection_count::<(K, V)>(next as u64)?;
        self.reserve_map(values, 1)
    }

    fn collection_limit(&self) -> usize {
        self.materialization_limit.min(Self::MAX_COLLECTION_BYTES)
    }

    pub(crate) fn check_recursion_depth(depth: usize) -> Result<()> {
        let requested = depth.checked_add(1).unwrap_or(usize::MAX);
        if depth >= Self::MAX_RECURSION_DEPTH {
            return Err(ErrorKind::RecursionLimit {
                requested,
                max: Self::MAX_RECURSION_DEPTH,
            }
            .into());
        }
        Ok(())
    }

    pub(crate) fn peek(&mut self, cnt: usize) -> Result<&[u8]> {
        self.ensure(cnt)?;

        match &self.input {
            Input::Slice(data) => Ok(&data[..cnt]),
            Input::Stream(_) => Ok(&self.buffer[self.cursor..self.cursor + cnt]),
        }
    }

    pub(crate) fn bytes(&mut self) -> Result<&[u8]> {
        self.ensure(1)?;

        match &self.input {
            Input::Slice(data) => Ok(data),
            Input::Stream(_) => Ok(&self.buffer[self.cursor..]),
        }
    }

    pub(crate) fn advance(&mut self, cnt: usize) -> Result<()> {
        self.ensure(cnt)?;

        match &mut self.input {
            Input::Slice(data) => *data = &data[cnt..],
            Input::Stream(_) => self.cursor += cnt,
        }

        Ok(())
    }

    pub(crate) fn get_u8(&mut self) -> Result<u8> {
        Ok(self.read(1)?[0])
    }

    pub(crate) fn get_u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read(2)?.try_into().unwrap()))
    }

    pub(crate) fn get_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read(4)?.try_into().unwrap()))
    }

    pub(crate) fn get_u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read(8)?.try_into().unwrap()))
    }

    pub(crate) fn get_u128(&mut self) -> Result<u128> {
        Ok(u128::from_le_bytes(self.read(16)?.try_into().unwrap()))
    }

    pub(crate) fn get_f32(&mut self) -> Result<f32> {
        Ok(f32::from_le_bytes(self.read(4)?.try_into().unwrap()))
    }
}

/// Reserve parser-owned vector capacity without allowing the collection to
/// grow beyond the bounded derived-data budget.
pub(crate) fn reserve_collection<T>(values: &mut Vec<T>, additional: usize) -> Result<()> {
    let next = values.len().checked_add(additional).ok_or(ErrorKind::CollectionLimit {
        requested: usize::MAX,
        max: Reader::MAX_COLLECTION_BYTES,
    })?;
    let requested = next
        .checked_mul(size_of::<T>())
        .ok_or(ErrorKind::CollectionLimit {
            requested: usize::MAX,
            max: Reader::MAX_COLLECTION_BYTES,
        })?;
    if requested > Reader::MAX_COLLECTION_BYTES {
        return Err(ErrorKind::CollectionLimit {
            requested,
            max: Reader::MAX_COLLECTION_BYTES,
        }
        .into());
    }

    values
        .try_reserve(additional)
        .map_err(|_| ErrorKind::AllocationFailed { requested })?;
    Ok(())
}

/// Copy parser-owned byte data through the bounded derived-data budget.
pub(crate) fn copy_bytes(values: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    reserve_collection(&mut output, values.len())?;
    output.extend_from_slice(values);
    Ok(output)
}

/// Reserve parser-owned map capacity without allowing the collection to grow
/// beyond the bounded derived-data budget.
pub(crate) fn reserve_collection_map<K: Eq + Hash, V>(
    values: &mut HashMap<K, V>,
    additional: usize,
) -> Result<()> {
    let next = values.len().checked_add(additional).ok_or(ErrorKind::CollectionLimit {
        requested: usize::MAX,
        max: Reader::MAX_COLLECTION_BYTES,
    })?;
    let requested = next
        .checked_mul(size_of::<(K, V)>())
        .ok_or(ErrorKind::CollectionLimit {
            requested: usize::MAX,
            max: Reader::MAX_COLLECTION_BYTES,
        })?;
    if requested > Reader::MAX_COLLECTION_BYTES {
        return Err(ErrorKind::CollectionLimit {
            requested,
            max: Reader::MAX_COLLECTION_BYTES,
        }
        .into());
    }

    values
        .try_reserve(additional)
        .map_err(|_| ErrorKind::AllocationFailed { requested })?;
    Ok(())
}

/// Reserve parser-owned set capacity without allowing the collection to grow
/// beyond the bounded derived-data budget.
pub(crate) fn reserve_collection_set<T: Eq + Hash>(
    values: &mut std::collections::HashSet<T>,
    additional: usize,
) -> Result<()> {
    let next = values.len().checked_add(additional).ok_or(ErrorKind::CollectionLimit {
        requested: usize::MAX,
        max: Reader::MAX_COLLECTION_BYTES,
    })?;
    let requested = next
        .checked_mul(size_of::<T>())
        .ok_or(ErrorKind::CollectionLimit {
            requested: usize::MAX,
            max: Reader::MAX_COLLECTION_BYTES,
        })?;
    if requested > Reader::MAX_COLLECTION_BYTES {
        return Err(ErrorKind::CollectionLimit {
            requested,
            max: Reader::MAX_COLLECTION_BYTES,
        }
        .into());
    }

    values
        .try_reserve(additional)
        .map_err(|_| ErrorKind::AllocationFailed { requested })?;
    Ok(())
}

/// Collect fallible parser results into a bounded vector.
pub(crate) fn collect_results<T, I>(items: I) -> Result<Vec<T>>
where
    I: IntoIterator<Item = Result<T>>,
{
    let items = items.into_iter();
    let mut values = Vec::new();
    let (lower_bound, _) = items.size_hint();
    reserve_collection(&mut values, lower_bound)?;
    for item in items {
        reserve_collection(&mut values, 1)?;
        values.push(item?);
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::{checked_reader_end, BlobSpoolBudget, Reader, ReaderBlob};
    use std::cell::Cell;
    use std::io::{self, Cursor, Read};
    use std::rc::Rc;
    use std::sync::Mutex;

    static SPOOL_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct TestSpoolBudget {
        current: Cell<u64>,
        peak: Cell<u64>,
        max: u64,
    }

    impl BlobSpoolBudget for TestSpoolBudget {
        fn reserve(&self, bytes: u64) -> bool {
            let Some(next) = self.current.get().checked_add(bytes) else {
                return false;
            };
            if next > self.max {
                return false;
            }
            self.current.set(next);
            self.peak.set(self.peak.get().max(next));
            true
        }

        fn release(&self, bytes: u64) {
            self.current.set(self.current.get().saturating_sub(bytes));
        }
    }

    struct InterruptOnce {
        interrupted: bool,
        data: Cursor<Vec<u8>>,
    }

    impl Read for InterruptOnce {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "retry"));
            }
            self.data.read(buffer)
        }
    }

    #[test]
    fn read_vec_rejects_payloads_above_materialization_limit() {
        let mut reader = Reader::from_reader(Cursor::new(Vec::<u8>::new()));

        let error = reader
            .read_vec(Reader::MAX_MATERIALIZED_BYTES + 1)
            .unwrap_err();

        assert!(error.is_resource_limit());
    }

    #[test]
    fn read_vec_u64_rejects_payloads_above_materialization_limit() {
        let mut reader = Reader::from_reader(Cursor::new(Vec::<u8>::new()));

        let error = reader
            .read_vec_u64((Reader::MAX_MATERIALIZED_BYTES as u64) + 1)
            .unwrap_err();

        assert!(error.is_resource_limit());
    }

    #[test]
    fn recursion_depth_rejects_the_first_level_beyond_limit() {
        assert!(Reader::check_recursion_depth(Reader::MAX_RECURSION_DEPTH).is_err());
    }

    #[test]
    fn read_vec_rejects_cumulative_materialization_limit() {
        let mut reader = Reader::from_reader_with_materialization_limit(
            Cursor::new(b"abcdef".to_vec()),
            5,
        );

        assert_eq!(reader.read_vec(3).unwrap(), b"abc");
        let error = reader.read_vec(3).unwrap_err();

        assert!(error.is_resource_limit());
    }

    #[test]
    fn stream_window_rejects_unbounded_read_before_growth() {
        let mut reader = Reader::from_reader_with_materialization_limit(
            Cursor::new(Vec::<u8>::new()),
            64,
        );

        let error = reader.read(65).unwrap_err();

        assert!(error.is_resource_limit());
        assert!(reader.buffer.is_empty());
    }

    #[test]
    fn stream_window_rejects_a_single_refill_overflow() {
        let mut reader = Reader::from_reader(Cursor::new(Vec::<u8>::new()));

        let error = reader.read(Reader::REFILL_SIZE + 1).unwrap_err();

        assert!(error.is_resource_limit());
        assert!(reader.buffer.is_empty());
    }

    #[test]
    fn stream_reader_retries_interrupted_reads() {
        let source = InterruptOnce {
            interrupted: false,
            data: Cursor::new(b"ok".to_vec()),
        };
        let mut reader = Reader::from_reader(source);

        assert_eq!(reader.read(2).unwrap(), b"ok");
    }

    #[test]
    fn stream_blob_uses_a_private_spool_without_materializing_payload() {
        let _lock = SPOOL_TEST_LOCK.lock().unwrap();
        let payload = (0..(Reader::REFILL_SIZE * 2 + 17))
            .map(|value| (value % 251) as u8)
            .collect::<Vec<_>>();
        let mut reader = Reader::from_reader_with_materialization_limit(
            Cursor::new(payload.clone()),
            Reader::REFILL_SIZE,
        );

        let blob = reader.read_blob(payload.len() as u64).unwrap();
        assert_eq!(reader.materialized_bytes, 0);

        let path = match &blob {
            ReaderBlob::Spool(spool) => {
                assert_eq!(spool.length(), payload.len() as u64);
                let mut reader = spool.open_reader().unwrap();
                let mut data = Vec::new();
                reader.read_to_end(&mut data).unwrap();
                assert_eq!(data, payload);
                spool.path.clone()
            }
            ReaderBlob::Memory(_) => panic!("stream-backed blobs must use a spool"),
        };

        assert!(path.exists());
        drop(blob);
        assert!(!path.exists());
    }

    #[test]
    fn stream_blob_accounts_each_extent_until_spool_drop() {
        let _lock = SPOOL_TEST_LOCK.lock().unwrap();
        let payload = (0..(Reader::REFILL_SIZE + 17))
            .map(|value| (value % 251) as u8)
            .collect::<Vec<_>>();
        let budget = Rc::new(TestSpoolBudget {
            current: Cell::new(0),
            peak: Cell::new(0),
            max: payload.len() as u64,
        });
        let mut reader = Reader::from_reader_with_options(
            Cursor::new(payload.clone()),
            Reader::MAX_MATERIALIZED_BYTES,
            None,
            Some(budget.clone()),
        );

        let blob = reader.read_blob(payload.len() as u64).unwrap();
        assert_eq!(budget.current.get(), payload.len() as u64);
        assert_eq!(budget.peak.get(), payload.len() as u64);
        drop(blob);
        assert_eq!(budget.current.get(), 0);
    }

    #[test]
    fn nested_blob_reader_retains_the_outer_spool_budget() {
        let _lock = SPOOL_TEST_LOCK.lock().unwrap();
        let budget = Rc::new(TestSpoolBudget {
            current: Cell::new(0),
            peak: Cell::new(0),
            max: 2,
        });
        let mut reader = Reader::from_reader_with_options(
            Cursor::new(b"ab".to_vec()),
            Reader::MAX_MATERIALIZED_BYTES,
            None,
            Some(budget.clone()),
        );

        let outer = reader.read_blob(1).unwrap();
        assert_eq!(budget.current.get(), 1);

        let mut nested_reader = outer.open_reader_with_spool_options().unwrap();
        let nested = nested_reader.read_blob(1).unwrap();
        assert_eq!(budget.current.get(), 2);

        drop(nested);
        assert_eq!(budget.current.get(), 1);
        drop(nested_reader);
        drop(outer);
        assert_eq!(budget.current.get(), 0);
    }

    #[test]
    fn stream_blob_rejects_unreserved_temporary_extent() {
        let _lock = SPOOL_TEST_LOCK.lock().unwrap();
        let budget = Rc::new(TestSpoolBudget {
            current: Cell::new(0),
            peak: Cell::new(0),
            max: 0,
        });
        let mut reader = Reader::from_reader_with_options(
            Cursor::new(b"x".to_vec()),
            Reader::MAX_MATERIALIZED_BYTES,
            None,
            Some(budget.clone()),
        );

        let error = reader
            .read_blob(1)
            .err()
            .expect("temporary budget refusal must fail the blob");

        assert!(error.is_resource_limit());
        assert_eq!(budget.current.get(), 0);
    }

    #[test]
    fn zero_length_stream_blob_does_not_create_a_spool() {
        let _lock = SPOOL_TEST_LOCK.lock().unwrap();
        let mut reader = Reader::from_reader(Cursor::new(b"unused".to_vec()));

        let blob = reader.read_blob(0).unwrap();

        match blob {
            ReaderBlob::Memory(data) => assert!(data.is_empty()),
            ReaderBlob::Spool(_) => panic!("empty stream-backed blobs need no spool"),
        }
    }

    #[test]
    fn stream_blob_removes_partial_spool_after_source_truncation() {
        let _lock = SPOOL_TEST_LOCK.lock().unwrap();
        let payload = b"short blob";
        let mut reader = Reader::from_reader(Cursor::new(payload.to_vec()));

        let error = reader
            .read_blob((payload.len() + 1) as u64)
            .err()
            .expect("a truncated stream-backed blob must fail");

        assert_eq!(error.to_string(), "Unexpected end of file");
        let leftovers = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("onenote-parser-{}-", std::process::id()))
            })
            .count();
        assert_eq!(leftovers, 0, "truncated blob left a parser spool behind");
    }

    #[cfg(unix)]
    #[test]
    fn stream_blob_spool_is_owner_readable_only() {
        use std::os::unix::fs::PermissionsExt;

        let _lock = SPOOL_TEST_LOCK.lock().unwrap();
        let mut reader = Reader::from_reader(Cursor::new(b"private".to_vec()));
        let blob = reader.read_blob(7).unwrap();
        let path = match &blob {
            ReaderBlob::Spool(spool) => spool.path.clone(),
            ReaderBlob::Memory(_) => panic!("stream-backed blobs must use a spool"),
        };

        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn reader_offset_addition_overflow_is_resource_visible() {
        let error = checked_reader_end(usize::MAX, 1, Reader::MAX_MATERIALIZED_BYTES)
            .expect_err("reader offset overflow must fail closed");

        assert!(error.is_resource_limit());
    }

    #[test]
    fn collection_count_rejects_over_budget() {
        let reader = Reader::new(&[]);
        let count = (Reader::MAX_COLLECTION_BYTES / size_of::<u64>() + 1) as u64;

        let error = reader.checked_collection_count::<u64>(count).unwrap_err();

        assert!(error.is_resource_limit());
    }
}
