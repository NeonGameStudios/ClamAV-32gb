use crate::errors::Result;
use crate::fsshttpb::data::object_types::ObjectType;
use crate::fsshttpb::data::stream_object::ObjectHeader;
use crate::fsshttpb::data_element::DataElement;
use crate::reader::{Reader as RawReader, ReaderBlob};
use crate::Reader;
use std::{
    convert::TryFrom,
    fmt,
    io::{self, Cursor, Read},
};

/// An object data blob.
///
/// See [\[MS-FSSHTTPB\] 2.2.1.12.8]
///
/// [\[MS-FSSHTTPB\] 2.2.1.12.8]: https://docs.microsoft.com/en-us/openspecs/sharepoint_protocols/ms-fsshttpb/d36dd2b4-bad1-441b-93c7-adbe3069152c
pub(crate) struct ObjectDataBlob(ReaderBlob);

impl ObjectDataBlob {
    pub(crate) fn len(&self) -> u64 {
        match &self.0 {
            ReaderBlob::Memory(data) => data.len() as u64,
            ReaderBlob::Spool(spool) => spool.length(),
        }
    }

    pub(crate) fn read_all(&self) -> Result<Vec<u8>> {
        match &self.0 {
            ReaderBlob::Memory(data) => crate::reader::copy_bytes(data),
            ReaderBlob::Spool(spool) => {
                let length = usize::try_from(spool.length()).map_err(|_| {
                    crate::errors::ErrorKind::ResourceLimit {
                        requested: usize::MAX,
                        max: RawReader::MAX_COLLECTION_BYTES,
                    }
                })?;
                if length > RawReader::MAX_COLLECTION_BYTES {
                    return Err(crate::errors::ErrorKind::CollectionLimit {
                        requested: length,
                        max: RawReader::MAX_COLLECTION_BYTES,
                    }
                    .into());
                }
                let mut data = Vec::new();
                crate::reader::reserve_collection(&mut data, length)?;
                let mut reader = spool.open_reader()?;
                reader.read_to_end(&mut data)?;
                if data.len() != length {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "OneNote parser blob spool ended early",
                    )
                    .into());
                }
                Ok(data)
            }
        }
    }

    pub(crate) fn open_reader(&self) -> Result<Box<dyn Read + '_>> {
        match &self.0 {
            ReaderBlob::Memory(data) => Ok(Box::new(Cursor::new(data.as_slice()))),
            ReaderBlob::Spool(spool) => Ok(Box::new(spool.open_reader()?)),
        }
    }
}

impl fmt::Debug for ObjectDataBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectDataBlob({} bytes)", self.len())
    }
}

impl DataElement {
    pub(crate) fn parse_object_data_blob(reader: Reader) -> Result<ObjectDataBlob> {
        ObjectHeader::try_parse(reader, ObjectType::ObjectDataBlob)?;

        let size = crate::fsshttpb::data::compact_u64::CompactU64::parse(reader)?.value();
        let data = reader.read_blob(size)?;

        ObjectHeader::try_parse_end_8(reader, ObjectType::DataElement)?;

        Ok(ObjectDataBlob(data))
    }
}
