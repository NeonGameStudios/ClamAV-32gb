use crate::errors::Result;
use crate::fsshttpb::data::compact_u64::CompactU64;
use crate::reader::ReaderBlob;
use crate::Reader;

/// A byte array with the length determined by a `CompactU64`.
///
/// See [\[MS-FSSHTTPB\] 2.2.1.3].
///
/// [\[MS-FSSHTTPB\] 2.2.1.3]: https://docs.microsoft.com/en-us/openspecs/sharepoint_protocols/ms-fsshttpb/6bdda105-af7f-4757-8dbe-0c7f3100647e
pub(crate) struct BinaryItem(ReaderBlob);

impl BinaryItem {
    pub(crate) fn parse(reader: Reader) -> Result<BinaryItem> {
        let size = CompactU64::parse(reader)?.value();
        let data = reader.read_blob(size)?;

        Ok(BinaryItem(data))
    }

    pub(crate) fn value(self) -> ReaderBlob {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::BinaryItem;
    use crate::reader::{Reader, ReaderBlob};
    use std::io::{Cursor, Read};

    #[test]
    fn stream_binary_items_use_the_bounded_blob_path() {
        let mut encoded = vec![0x15]; // compact-u64 value 10
        encoded.extend_from_slice(b"0123456789");
        let mut reader = Reader::from_reader(Cursor::new(encoded));

        let item = BinaryItem::parse(&mut reader).expect("binary item should parse");
        let mut payload = item.value();
        let mut output = Vec::new();
        match &mut payload {
            ReaderBlob::Spool(spool) => {
                spool
                    .open_reader()
                    .expect("spool should open")
                    .read_to_end(&mut output)
                    .expect("spool should be readable");
            }
            ReaderBlob::Memory(_) => panic!("stream binary items must use a private spool"),
        }

        assert_eq!(output, b"0123456789");
    }
}
