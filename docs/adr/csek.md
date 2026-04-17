# Customer-supplied Encryption Key

Encryption algorithms supported: `aegis-256`, `aes-256-gcm`. Both require a 32-byte symmetric key.

At the basin level, users configure the encryption algorithm (or none, the default) to be used for streams created in that basin.

New streams materialize this algorithm into their metadata when created. It is immutable for the lifetime of a stream and cannot be reconfigured.

Data plane `append` and `read` operations look for the `s2-encryption-key` header, where it must be provided as a base64 string if encryption is enabled.

The encryption key should stay consistent for a given stream, but this is not enforced by the service.
- If no key is provided when required, the `append` or `read` operation will fail.
- The same key used to encrypt when appending must be used when reading records.
- Appends will succeed even if a different key is provided than previously used.

Encryption algorithm is one of the pieces of stream-level metadata returned when listing streams.
