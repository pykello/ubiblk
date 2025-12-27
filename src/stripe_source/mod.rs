use crate::{
    block_device::{NullBlockDevice, SharedBuffer},
    vhost_backend::{build_block_device, Options},
    KeyEncryptionCipher, Result,
};

/// A source from which stripes can be fetched.
pub trait StripeSource {
    /// Request to fetch a stripe.
    fn request(&mut self, stripe_id: usize, buffer: SharedBuffer) -> Result<()>;
    /// Poll for completed stripe fetch requests.
    fn poll(&mut self) -> Vec<(usize, bool)>;
    /// Check if there are any pending requests.
    fn busy(&self) -> bool;
    /// Get the sector count of the stripe source.
    fn sector_count(&self) -> u64;
}

mod bdev;
pub use bdev::BlockDeviceStripeSource;

pub struct StripeSourceBuilder {
    options: Options,
    kek: KeyEncryptionCipher,
    stripe_sector_count: u64,
}

impl StripeSourceBuilder {
    pub fn new(options: Options, kek: KeyEncryptionCipher, stripe_sector_count: u64) -> Self {
        Self {
            options,
            kek,
            stripe_sector_count,
        }
    }

    pub fn build(&self) -> Result<Box<dyn StripeSource>> {
        if let Some(image_path) = &self.options.image_path {
            let block_device = build_block_device(image_path, &self.options, self.kek.clone())?;
            return Ok(Box::new(BlockDeviceStripeSource::new(
                block_device.as_ref(),
                self.stripe_sector_count,
            )?));
        }
        Ok(Box::new(BlockDeviceStripeSource::new(
            NullBlockDevice::new().as_ref(),
            self.stripe_sector_count,
        )?))
    }
}
