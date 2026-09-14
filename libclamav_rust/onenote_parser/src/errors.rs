//! OneNote parsing error handling.

#[cfg(feature = "backtrace")]
use std::backtrace::Backtrace;
use std::borrow::Cow;
use std::{io, string};
use thiserror::Error;

/// The result of parsing a OneNote file.
pub type Result<T> = std::result::Result<T, Error>;

/// A parsing error.
///
/// If the crate is compiled with the `backtrace` feature enabled, the
/// parsing error struct will contain a backtrace of the location where
/// the error occured. The backtrace can be accessed using
/// [`std::error::Error::backtrace()`].
#[derive(Error, Debug)]
#[error("{kind}")]
pub struct Error {
    kind: ErrorKind,

    #[cfg(feature = "backtrace")]
    backtrace: Backtrace,
}

impl From<ErrorKind> for Error {
    #[cfg(feature = "backtrace")]
    fn from(kind: ErrorKind) -> Self {
        Error {
            kind,
            backtrace: Backtrace::capture(),
        }
    }

    #[cfg(not(feature = "backtrace"))]
    fn from(kind: ErrorKind) -> Self {
        Error { kind }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        ErrorKind::from(err).into()
    }
}

impl From<std::string::FromUtf16Error> for Error {
    fn from(err: std::string::FromUtf16Error) -> Self {
        ErrorKind::from(err).into()
    }
}

impl From<widestring::error::MissingNulTerminator> for Error {
    fn from(err: widestring::error::MissingNulTerminator) -> Self {
        ErrorKind::from(err).into()
    }
}

impl From<uuid::Error> for Error {
    fn from(err: uuid::Error) -> Self {
        ErrorKind::from(err).into()
    }
}

impl Error {
    /// Return whether this is a parser-owned materialization limit failure.
    pub fn is_resource_limit(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::ResourceLimit { .. }
                | ErrorKind::TemporaryLimit { .. }
                | ErrorKind::CollectionLimit { .. }
                | ErrorKind::AllocationFailed { .. }
                | ErrorKind::RecursionLimit { .. }
        )
    }

    /// Consume the parsing error and return its underlying I/O error, when
    /// parsing stopped on an input read.
    pub fn into_io_error(self) -> Option<io::Error> {
        match self.kind {
            ErrorKind::IO { err } => Some(err),
            _ => None,
        }
    }
}

/// Details about a parsing error
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ErrorKind {
    /// Hit the end of the OneNote file before it was expected.
    #[error("Unexpected end of file")]
    UnexpectedEof,

    /// A declared parser-owned payload exceeds the bounded materialization
    /// limit.
    #[error("Declared payload of {requested} bytes exceeds the materialization limit of {max} bytes")]
    ResourceLimit { requested: usize, max: usize },

    /// Parser-owned temporary storage could not be reserved.
    #[error("OneNote parser temporary storage reservation failed for {requested} bytes")]
    TemporaryLimit { requested: u64 },

    /// A count-driven parser collection exceeds its bounded size limit.
    #[error("Declared collection of {requested} bytes exceeds the collection limit of {max} bytes")]
    CollectionLimit { requested: usize, max: usize },

    /// The bounded payload buffer could not be grown.
    #[error("Unable to allocate {requested} bytes for a OneNote payload")]
    AllocationFailed { requested: usize },

    /// A recursive OneNote structure exceeds the parser's depth limit.
    #[error("Recursion depth of {requested} exceeds the recursion limit of {max}")]
    RecursionLimit { requested: usize, max: usize },

    /// The parser was asked to process a table-of-contents file that turned out not to be one.
    #[error("Not a table of contents file: {file}")]
    NotATocFile { file: String },

    /// The parser was asked to process a section file that turned out not to be one.
    #[error("Not a section file: {file}")]
    NotASectionFile { file: String },

    /// When parsing a section group the table-of-contents file for this group was found to be missing.
    #[error("Table of contents file is missing in dir {dir}")]
    TocFileMissing { dir: String },

    /// Malformed data was encountered when parsing the OneNote file.
    #[error("Malformed data: {0}")]
    MalformedData(Cow<'static, str>),

    /// Malformed data was encountered when parsing the OneNote data.
    #[error("Malformed OneNote data: {0}")]
    MalformedOneNoteData(Cow<'static, str>),

    /// Malformed data was encountered when parsing the OneNote file contents.
    #[error("Malformed OneNote file data: {0}")]
    MalformedOneNoteFileData(Cow<'static, str>),

    /// Malformed data was encountered when parsing the OneStore data.
    #[error("Malformed OneStore data: {0}")]
    MalformedOneStoreData(Cow<'static, str>),

    /// Malformed data was encountered when parsing the FSSHTTPB data.
    #[error("Malformed FSSHTTPB data: {0}")]
    MalformedFssHttpBData(Cow<'static, str>),

    /// A malformed UUID was encountered
    #[error("Invalid UUID: {err}")]
    InvalidUuid {
        #[from]
        err: uuid::Error,
    },

    /// An I/O failure was encountered during parsing.
    #[error("I/O failure: {err}")]
    IO {
        #[from]
        err: io::Error,
    },

    /// A malformed UTF-16 string was encountered during parsing.
    #[error("Malformed UTF-16 string: {err}")]
    Utf16Error {
        #[from]
        err: string::FromUtf16Error,
    },

    /// A UTF-16 string without a null terminator was encountered during parsing.
    #[error("UTF-16 string is missing null terminator: {err}")]
    Utf16MissingNull {
        #[from]
        err: widestring::error::MissingNulTerminator,
    },
}
