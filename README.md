# C# JWKs - JSON Web Keys (RFC7517)
This repository provides an implementation in C# of RFC7517 (JSON Web Keys).

`Notice: The current implementation has been used in a production environment.` 
<br>`However, no support will be offered for this project. Here be dragons. Please fill any bugs you may find.`

## Getting Started

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.

All details of the implementation are based on the following literature:
* [RFC 7517 - JSON Web Keys](https://www.rfc-editor.org/rfc/rfc7517.txt)
* [RFC 7518 - JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518.txt)

Supported Key Types for creating new JWKs (with the corresponding intended algorithm):

|                | Algorithm | Support |
|----------------|:-----------------------------|:-------------------------------|
| RSA            | RS256, RS384, RS512          | :white_check_mark:
| Eliptic Curves | ES256, ES384, ES512          | :white_check_mark:
| HMAC           | HS256, HS384, HS512          | :negative_squared_cross_mark:
| AES            | A128GCMKW, A192GCMKW, A256GCMKW    | :negative_squared_cross_mark:
| None           | none                         | :negative_squared_cross_mark: 

|                               | Meaning |
|-------------------------------|:-------------                         |
| :white_check_mark:            | Fully implemented and tested           |
| :negative_squared_cross_mark: | Currently being implemented / Untested |
| :x:                           | Not implemented yet                    |

Building JSON Web Key Sets is also supported.

## Build

The following configuration has been succesfully tested for building and running the project:

* .NET 8 / netstandard2.0

![Build status](https://github.com/alexzautke/JWK/actions/workflows/main.yml/badge.svg)

## Limitations

### Project TODOs
- [] Complete support for all JWK key types
- [] Support for EdDSA keys (See [RFC8037](https://www.rfc-editor.org/rfc/rfc8037))
- [] Support for x5u, x5c, x5t, x5t#S256 parameters in a JWK (they are preserved through a round trip, but not interpreted)
- [x] Check for required key parameters on deserialization (see Validation)
- [] Follow RFC7517 security conciderations guidelines

## INSTALL

### NuGet

https://www.nuget.org/packages/CreativeCode.JWK/

``dotnet add package CreativeCode.JWK``

### Building from source

1. ``git clone https://github.com/alexzautke/JWK.git``
2. ``dotnet pack -c Release``
3. [Install NuGet package from local source](https://docs.microsoft.com/en-us/nuget/consume-packages/ways-to-install-a-package)

## Usage

See [JWK Example](https://gist.github.com/alexzautke/ef0466afb1ba6d348310dfff0fc0969b)

## Validation

The constructors of `JWK` and `JWKS` throw on the first problem they run into. `TryParse` instead collects every
reason why a key was rejected, which is what you want if those reasons have to be reported back to whoever supplied
the key:

```csharp
if (!JWK.TryParse(json, out var jwk, out var errors))
    return string.Join(" ", errors);
```

What is checked is key validity as RFC 7517 and RFC 7518 define it: a supported key type, the presence and encoding
of the key parameters that key type requires, a known curve, coordinates padded to the size of that curve, a public
key which really is a point on the curve it claims, every entry of the `keys` of a key set being a JSON object, and
unique key ids within a key set. `JWKS.TryParse` ignores a key whose key type is not supported, as RFC 7517 -
Section 5 recommends, and only rejects the set if no key of a supported key type remains; `JWK.TryParse` rejects such
a key.

What is *not* checked is policy - which algorithms you accept, how large a key has to be, or whether a `kid` is
required. That is yours to decide; `GetKeySizeInBits()` gives you the measurement to decide it with.

## Export

`Export` says which members of the key it writes:

```csharp
jwk.Export();                    // KeyMembers.Public - the public key, safe to hand out
jwk.Export(KeyMembers.All);      // every member, including the private key material
```

A member this library could not interpret - anything on a key type it has no support for, or a private member of
its own - is withheld by a public export, because it cannot be known whether it carries key material. The
certificate members registered in RFC 7517 (`x5u`, `x5c`, `x5t`, `x5t#S256`) are public by definition and are
always written.

## Test

Simply run ``dotnet test`` in the root folder of the project. All tests should be passing.

## Security Conciderations

More details about security risks associated with JWKs are documented in [RFC section 9](https://tools.ietf.org/html/rfc7517#section-9).

### Key Provenance and Trust

`One should place no more trust in the data cryptographically secured
   by a key than in the method by which it was obtained and in the
   trustworthiness of the entity asserting an association with the key.`

Please follow the recommendations on how to obtain a JWK.

Current issues:
- This library does currently not support the "x5c" element within a JWK. It would enable the user to provide additional information about the authorship of the key.

### Preventing Disclosure of Non-public Key Information

`Private and symmetric keys MUST be protected from disclosure to
   unintended parties.`

Current issues:
- This library does currently not use any kind of protected memory to store the generated key associated with a JWK.

### Key Entropy and Random Values

`Keys are only as strong as the amount of entropy used to generate
   them.`
Current issues:
- This library does currenty not check if "enough" entropy is available on a system to generate a secure key.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details 
