use crate::errors::{ErrorKind, Result};
use std::{
    collections::HashMap,
    convert::TryInto,
    hash::Hash,
    io::Read,
    mem::size_of,
};

enum Input<'a> {
    Slice(&'a [u8]),
    Stream(Box<dyn Read + 'a>),
}

pub(crate) struct Reader<'a> {
    input: Input<'a>,
    buffer: Vec<u8>,
    cursor: usize,
    materialized_bytes: usize,
    materialization_limit: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const REFILL_SIZE: usize = 64 * 1024;
    pub(crate) const MAX_MATERIALIZED_BYTES: usize = 256 * 1024 * 1024;
    pub(crate) const MAX_COLLECTION_BYTES: usize = 64 * 1024 * 1024;

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
        }
    }

    pub(crate) fn from_reader<R: Read + 'a>(reader: R) -> Reader<'a> {
        Self::from_reader_with_materialization_limit(reader, Self::MAX_MATERIALIZED_BYTES)
    }

    fn from_reader_with_materialization_limit<R: Read + 'a>(
        reader: R,
        materialization_limit: usize,
    ) -> Reader<'a> {
        Reader {
            input: Input::Stream(Box::new(reader)),
            buffer: Vec::new(),
            cursor: 0,
            materialized_bytes: 0,
            materialization_limit,
        }
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
            self.buffer
                .try_reserve(requested)
                .map_err(|_| ErrorKind::AllocationFailed {
                    requested: cnt,
                })?;
            self.buffer.resize(start + requested, 0);
            let read = match &mut self.input {
                Input::Stream(reader) => reader.read(&mut self.buffer[start..])?,
                Input::Slice(_) => unreachable!(),
            };
            if read == 0 {
                self.buffer.truncate(start);
                return Err(ErrorKind::UnexpectedEof.into());
            }
            self.buffer.truncate(start + read);
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
                self.cursor += cnt;
                Ok(&self.buffer[start..start + cnt])
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

#[cfg(test)]
mod tests {
    use super::Reader;
    use std::io::Cursor;

    #[test]
    fn read_vec_rejects_payloads_above_materialization_limit() {
        let mut reader = Reader::from_reader(Cursor::new(Vec::<u8>::new()));

        let error = reader
            .read_vec(Reader::MAX_MATERIALIZED_BYTES + 1)
            .unwrap_err();

        assert!(error.is_resource_limit());
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
    fn collection_count_rejects_over_budget() {
        let reader = Reader::new(&[]);
        let count = (Reader::MAX_COLLECTION_BYTES / size_of::<u64>() + 1) as u64;

        let error = reader.checked_collection_count::<u64>(count).unwrap_err();

        assert!(error.is_resource_limit());
    }
}
