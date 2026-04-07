pub mod access;
pub mod basin;
pub mod config;
pub mod metrics;
pub mod resources;
pub mod stream;
mod strings;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ValidationError(pub String);

impl From<String> for ValidationError {
    fn from(value: String) -> Self {
        ValidationError(value)
    }
}

impl From<&str> for ValidationError {
    fn from(value: &str) -> Self {
        ValidationError(value.to_owned())
    }
}

impl From<crate::record::RecordDecryptionError> for ValidationError {
    fn from(value: crate::record::RecordDecryptionError) -> Self {
        match value {
            crate::record::RecordDecryptionError::AlgorithmMismatch { expected, actual } => {
                ValidationError(match expected {
                    Some(expected) => format!(
                        "ciphertext algorithm mismatch: expected {expected}, actual {actual}"
                    ),
                    None => {
                        format!("ciphertext algorithm mismatch: expected plain, actual {actual}")
                    }
                })
            }
            crate::record::RecordDecryptionError::AuthenticationFailed => {
                ValidationError("record decryption failed".to_owned())
            }
            crate::record::RecordDecryptionError::MalformedEncryptedRecord => {
                ValidationError("invalid encrypted record".to_owned())
            }
            crate::record::RecordDecryptionError::MeteredSizeMismatch { .. } => {
                ValidationError("invalid decrypted record metered size".to_owned())
            }
            crate::record::RecordDecryptionError::MalformedDecryptedRecord(_) => {
                ValidationError("invalid decrypted record".to_owned())
            }
        }
    }
}

impl From<crate::record::FencingTokenTooLongError> for ValidationError {
    fn from(e: crate::record::FencingTokenTooLongError) -> Self {
        ValidationError(e.to_string())
    }
}

impl From<resources::StartAfterLessThanPrefixError> for ValidationError {
    fn from(e: resources::StartAfterLessThanPrefixError) -> Self {
        ValidationError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::ValidationError;
    use crate::record::{RecordDecodeError, RecordDecryptionError};

    #[test]
    fn record_decryption_error_conversion_hides_internal_record_details() {
        let err: ValidationError = RecordDecryptionError::MalformedDecryptedRecord(
            RecordDecodeError::InvalidValue("HeaderFlag", "reserved bit set"),
        )
        .into();

        assert_eq!(err, ValidationError("invalid decrypted record".to_owned()));
    }

    #[test]
    fn record_decryption_error_conversion_hides_encrypted_record_details() {
        let err: ValidationError = RecordDecryptionError::MalformedEncryptedRecord.into();

        assert_eq!(err, ValidationError("invalid encrypted record".to_owned()));
    }

    #[test]
    fn record_decryption_error_conversion_includes_ciphertext_algorithm_for_plain_config() {
        let err: ValidationError = RecordDecryptionError::AlgorithmMismatch {
            expected: None,
            actual: crate::encryption::EncryptionAlgorithm::Aegis256,
        }
        .into();

        assert_eq!(
            err,
            ValidationError(
                "ciphertext algorithm mismatch: expected plain, actual aegis-256".to_owned()
            )
        );
    }
}
