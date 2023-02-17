
/// Error types for aggregate signatures.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AggrSignatureError {
    ///Aggregate nonce values differ
    #[error("Aggregate nonce values differ")]
    NonceInvalid,

    ///Aggregate signature is invalid
    #[error("Aggregate signature is invalid")]
    AggregateInvalid,
}