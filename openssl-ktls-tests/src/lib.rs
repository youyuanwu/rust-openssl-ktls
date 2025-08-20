#[cfg(test)]
pub mod async_ktls;
#[cfg(test)]
pub mod ktls;
#[cfg(test)]
pub mod utils;

pub mod exp;

#[cfg(test)]
// Global semaphore to serialize async mode tests (only 1 permit to prevent OpenSSL async/engine conflicts)
static SSL_TEST_SEMAPHORE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
