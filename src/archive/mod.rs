use crate::{
    crypt::{decode_optional_key_pair, encode_optional_key_pair},
    Result,
};
use serde::{Deserialize, Serialize};

/// Abstraction over a backend that can store and retrieve archived objects.
pub trait ArchiveStore {
    /// Store an object under the given `name`.
    fn start_put_object(&mut self, name: &str, data: &[u8]);
    /// Retrieve an object by its `name`.
    fn start_get_object(&mut self, name: &str);
    /// Poll for completed put operations.
    fn poll_puts(&mut self) -> Vec<(String, Result<()>)>;
    fn poll_gets(&mut self) -> Vec<(String, Result<Vec<u8>>)>;
    /// List all stored object names.
    fn list_objects(&self) -> Result<Vec<String>>;

    fn put_object(&mut self, name: &str, data: &[u8]) -> Result<()> {
        self.start_put_object(name, data);
        loop {
            let results = self.poll_puts();
            for (obj_name, result) in results {
                if obj_name == name {
                    return result;
                }
            }
        }
    }

    fn get_object(&mut self, name: &str) -> Result<Vec<u8>> {
        self.start_get_object(name);
        loop {
            let results = self.poll_gets();
            for (obj_name, result) in results {
                if obj_name == name {
                    return result;
                }
            }
        }
    }
}

/// Representation of `metadata.yaml` stored alongside archived stripes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArchiveMetadata {
    /// Number of sectors per stripe.
    pub stripe_sector_count: u64,
    /// Optional encrypted keys used for encrypting the archived data.
    #[serde(
        default,
        deserialize_with = "decode_optional_key_pair",
        serialize_with = "encode_optional_key_pair"
    )]
    pub encryption_key: Option<(Vec<u8>, Vec<u8>)>,
}

mod archiver;
mod fs_store;
mod s3_store;

pub use archiver::StripeArchiver;
pub use fs_store::FileSystemStore;
pub use s3_store::S3Store;

#[cfg(test)]
mod mem_store;

#[cfg(test)]
pub use mem_store::MemStore;
