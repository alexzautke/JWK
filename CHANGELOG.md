# CreativeCode.JWK Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## 0.8.0 - unreleased

### Added
- `JWK.TryParse` and `JWKS.TryParse`: a validating parse which reports every reason why a key is not a valid key instead of throwing on the first one. It checks what RFC 7517 / RFC 7518 require of a key - a supported key type, the presence and encoding of the parameters that key type requires, "use" and "key_ops" having the shape the RFC gives them, all of the other RSA private key parameters being present if any of them is, a known curve, coordinates padded to the size of that curve, a public key which really is a point on the curve it claims, and unique key ids within a key set. `JWKS.TryParse` ignores a key whose key type is not supported, as RFC 7517 - Section 5 recommends, and only rejects the set if no key of a supported key type remains. Which algorithms, key sizes or key ids are acceptable is policy and remains the caller's own decision. The constructors keep their current, throwing behaviour.
- `JWK.TryValidate` to run the same checks on a JWK which was not built from JSON.
- `JWK.ToRSAParameters` and `JWK.ToECParameters` to convert a JWK into the .NET key parameters, padding the values as `RSAParameters` and `ECParameters` expect them.
- `JWK.GetKeySizeInBits`, reporting the size of the modulus of an RSA key, the size of the curve of an elliptic curve key, or the length of the key material of a symmetric key.
- `EllipticCurve`, the curves registered for the "crv" parameter, with their object identifier, coordinate length and key size.
- `Base64Helper.TryBase64urlDecode`, which also rejects input outside the base64url alphabet. `Base64urlDecode` now throws `FormatException` instead of `Exception`.
- Support for the "oth" key parameter of a multi-prime RSA key. It is private key material, so it is only exported if the private key is exported.
- `PS256`, `PS384` and `PS512` are registered as algorithm names. Creating a new key for them is not supported.
- Members of a JWK which this library does not interpret (e.g. "x5c", "x5t#S256", or every member of a key type it has no support for) are kept in `JWK.AdditionalMembers` and written again by `Export`, instead of being dropped. Since the library cannot tell whether such a member is private key material, a public key export writes only the members registered in RFC 7517 - Section 4 and withholds the rest.

### Changed
- `JWK.Export` and `JWKS.Export` take a `KeyMembers` value instead of a bool: `Export(KeyMembers.Public)` (the default) or `Export(KeyMembers.All)`. `Export(true)` said nothing at the call site about what it would write out. The bool overload still works but is marked obsolete. `Serialize` on `Algorithm`, `KeyType` and `PublicKeyUse` takes the same `KeyMembers` value; it is defaulted, so an existing `Serialize()` call is unaffected.
- The symmetric key type is now spelled "oct" as registered in RFC 7518 - Section 6.1, instead of "OCT". A JWK which uses the previous spelling is still read correctly, but keys exported by this library change: their "kty" is now "oct".
- The curve of the ES512 algorithm is now named "P-521" as registered in RFC 7518 - Section 6.2.1.1, instead of "P-512". The key material itself is unchanged - it always was a secp521r1 key - and a JWK which uses the previous name is still read correctly.
- An unrecognized "alg" is no longer discarded. `Algorithm.TryGetAlgorithm` returns an instance carrying the name, with `IsRecognized` set to false, so that an algorithm this library does not know is no longer indistinguishable from an absent one and survives an export. The same applies to an unrecognized "key_ops" entry.
- Creating a new key for an algorithm this library cannot generate a key for (including `Algorithm.None`) now throws an `ArgumentException` instead of returning a JWK without a key type and without key parameters.
- A JWKS constructed from an empty set of keys now throws `ArgumentException` rather than `ArgumentNullException`. `JWKS.TryParse` reports it as an error instead of throwing.
- `KeyParameter.RSAKeyParameters`, `.ECKeyParameters` and `.OctKeyParameters` are declared as `IReadOnlyCollection<KeyParameter>` instead of `IEnumerable<KeyParameter>`, so that a caller can count them without enumerating them twice. Source compatible, but a recompile is needed.

### Fixed
- The key parameters of a generated RSA key were exported with the leading zero octets that `RSAParameters` pads its values with. A Base64urlUInt "MUST utilize the minimum number of octets needed to represent the value" (RFC 7518 - Section 2), so roughly one in fifty generated keys was not encoded as the RFC requires. `Base64Helper.Base64urlEncodeUInt` does this encoding.
- Member values were concatenated into the exported JSON without escaping, so a value containing a double quote - a "kid" or a key parameter read from an untrusted JWK, for example - produced JSON which could not be parsed again.
- "unwrapKey" was deserialized as `KeyOperation.DeriveKey` and "deriveKey" as `KeyOperation.DecryptKeyAndValidateDecryption`. Both now map to the operation they name.
- A "key_ops" entry which could not be recognized was added to the key operations as null, which threw a `NullReferenceException` when the JWK was exported again.
- A JWK whose only members could not be serialized (e.g. a key without a key type) produced JSON with a leading or stray comma.
- A string which looks like a date - a "kid" such as "2024-05-01T00:00:00Z", for example - was read as a date by Json.NET. `TryParse` then rejected the member as not being a JSON string, and the constructors replaced its value with a culture dependent rendering of that date (e.g. "05/01/2024 00:00:00"), which also changed members kept in `AdditionalMembers`. JWK and JWKS JSON is now read without date parsing, so every string keeps the value it was written with.

## 0.7.1 - 2023-03-29

### Changed
- Added a check to verify that the used keyLength for an RSA key is less than the max length support by the RSACryptoServiceProvider in the .NET SDK.

## 0.7.0 - 2023-03-26

### Added
- Add option in JWK constructor to provide custom key length for RSA key (Note: A minimum key length of 2048bit (NIST recommendation) is still enforced)

## 0.6.1 - 2023-02-08

### Fixed
- Fixed an issue that would cause a JsonWriterException when exporting multiple JWK objects in parallel

## 0.6.0 - 2022-12-30

### Added
- Added support for (de-)serialization of JSON Web Key Sets
- Added Base64Helper.cs for base64url encoding and decoding 

## 0.5.0 - 2022-11-14

### Changed
- Upgraded (test-)project dependencies

## 0.4.0 - 2021-01-25

### Changed
- The BuildWithOptions method has been removed. Corresponding constructors for the 'JWK' class have been added.
- 'keyParameters' has been renamed to 'KeyParameters'
- Added a constructor to initialize a JWK with key parameters
- KeyType has been removed from Algorithm
- Added a constructor to deserialize a JWK from a string
- Added TryGetAlgorithm, TryGetKeyType and TryGetPublicKeyUse to get the string representation of the corresponding object.

## 0.3.0 - 2020-12-21

### Changed
- JWK.KeyParts.Algorithm.Value has been renamed to .Name
- JWK.KeyParts.KeyParameters.Values is now publicly accessible
- JWK.KeyParts.KeyType.Type is now publicly accessible
- JWK.KeyParts.PublicKeyUse.KeyUse is now publicly accessible

### Fixed

- Issue #2 - key_ops is string, should be array

## 0.2.2 - 2019-01-09

### Changed
- Change TargetFramework to netstandard2.0 for improved compability.

## 0.2.1 - 2019-01-07

### Changed
- Improve literature reference for selecting HMAC key size

### Fixed
- Don't throw an exception when calling ToString() when calling to string on a symmetric key. Instead, return a message indicating that ToString() is not available for symmetric keys to avoid key exposure
- Fixed an invalid CryptographicException when calling when creating an HMAC key
- Fixed algorithm name when creating an ECCurve key with an unknown key length.

## 0.2.0 - 2018-12-29

### Added
- Added instructions on how to install CreativeCode.JWK library
- Added example code on how to create a JWK
- Provide performance information (building a JWK / serialize a JWK) in debug mode
- Serialize(bool shouldExportPrivateKey). Provide the JSON representation of the JWK.
- IsSymmetric(). Determines whether a JWK contains a symetric or asymetric key.

### Changed
- By default all properties of a JWK now contain a public getter
- Renamed JWKfromOptions to BuidlWithOptions
- An exception if thrown if Serialize() is called with shouldExportPrivateKey = false.

### Fixed
- If ECCurve name could not be parsed, no exception would be thrown

## 0.1.0 - 2018-12-24

### Added
- Initial release of NuGet package.
