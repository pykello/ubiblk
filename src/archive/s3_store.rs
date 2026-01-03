use std::sync::Arc;

use super::ArchiveStore;
use crate::{Result, UbiblkError};
use aws_config::BehaviorVersion;
use aws_sdk_s3::{config::Region, primitives::ByteStream, Client};

pub struct S3Store {
    client: Client,
    bucket: String,
    prefix: Option<String>,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl S3Store {
    pub fn new(
        bucket: String,
        region: String,
        endpoint: Option<String>,
        prefix: Option<String>,
    ) -> Result<Self> {
        let runtime =
            Arc::new(
                tokio::runtime::Runtime::new().map_err(|err| UbiblkError::ArchiveError {
                    description: format!("Failed to create async runtime: {err}"),
                })?,
            );

        let config = runtime.block_on(async {
            let mut loader =
                aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region));

            if let Some(endpoint) = endpoint {
                loader = loader.endpoint_url(endpoint);
            }

            loader.load().await
        });

        let client = Client::new(&config);
        let normalized_prefix = prefix.map(|p| p.trim_matches('/').to_string());

        Ok(Self {
            client,
            bucket,
            prefix: normalized_prefix,
            runtime,
        })
    }

    fn key_with_prefix(&self, name: &str) -> String {
        if let Some(prefix) = &self.prefix {
            format!("{}/{}", prefix, name)
        } else {
            name.to_string()
        }
    }

    fn strip_prefix<'a>(&self, key: &'a str) -> &'a str {
        if let Some(prefix) = &self.prefix {
            let prefix_with_sep = format!("{}/", prefix);
            key.strip_prefix(&prefix_with_sep).unwrap_or(key)
        } else {
            key
        }
    }
}

impl ArchiveStore for S3Store {
    fn put_object(&mut self, name: &str, data: &[u8]) -> Result<()> {
        let key = self.key_with_prefix(name);

        self.runtime
            .block_on(async {
                self.client
                    .put_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .body(ByteStream::from(data.to_vec()))
                    .send()
                    .await
            })
            .map_err(|err| UbiblkError::ArchiveError {
                description: format!("Failed to upload object to S3: {err}"),
            })?;

        Ok(())
    }

    fn get_object(&self, name: &str) -> Result<Vec<u8>> {
        let key = self.key_with_prefix(name);

        let output = self
            .runtime
            .block_on(async {
                self.client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .send()
                    .await
            })
            .map_err(|err| UbiblkError::ArchiveError {
                description: format!("Failed to fetch object from S3: {err}"),
            })?;

        let bytes = self
            .runtime
            .block_on(async { output.body.collect().await })
            .map_err(|err| UbiblkError::ArchiveError {
                description: format!("Failed to read object body: {err}"),
            })?;

        Ok(bytes.into_bytes().to_vec())
    }

    fn list_objects(&self) -> Result<Vec<String>> {
        let response = self
            .runtime
            .block_on(async {
                self.client
                    .list_objects_v2()
                    .bucket(&self.bucket)
                    .set_prefix(self.prefix.clone())
                    .send()
                    .await
            })
            .map_err(|err| UbiblkError::ArchiveError {
                description: format!("Failed to list objects in S3: {err}"),
            })?;

        let mut objects = Vec::new();
        for object in response.contents() {
            if let Some(key) = object.key() {
                objects.push(self.strip_prefix(key).to_string());
            }
        }

        Ok(objects)
    }
}
