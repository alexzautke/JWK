# C# JWKs - JSON Web Keys (RFC7517)
This repository provides an implementation in C# of RFC7517 (JSON Web Keys).

`Notice: The current implementation has not been used in a production environment.` 
<br>`Here be dragons. Please fill any bugs you may find.`

## Getting Started

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.

All details of the implementation are based on the following literature:
* [RFC 7517 - JSON Web Keys](https://www.rfc-editor.org/rfc/rfc7517.txt)
* [RFC 7518 - JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518.txt)

Supported Key Types for creating new JWKs (with the corresponding intended algorithm):

|                | Algorithm | Support |
|----------------|:-----------------------------|:-------------------------------|
| RSA            | RS256, RS384, RS512          | :negative_squared_cross_mark:
| Eliptic Curves | ES256, ES384, ES512          | :negative_squared_cross_mark:
| HMAC           | HS256, HS384, HS512          | :negative_squared_cross_mark:
| AES            | A128GCMKW, A192GCMKW, A256GCMKW    | :negative_squared_cross_mark:
| None           | none                         | :negative_squared_cross_mark: 

|                               | Meaning |
|-------------------------------|:-------------                         |
| :white_check_mark:            | Fully implemented and tested           |
| :negative_squared_cross_mark: | Currently being implemented / Untested |
| :x:                           | Not implemented yet                    |

## Build

The following configuration has been succesfully tested for building and running the project:
* Visual Studio for Mac - Version 7.6.8 (build 38)
* .Net Core - Version 2.1.302

[![Build Status](https://travis-ci.com/alexzautke/JWK.svg?branch=master)](https://travis-ci.com/alexzautke/JWK)

## Limitations

### Project TODOs
- [] Complete support for all JWK key types
- [] Support for EdDSA keys
- [] Support for exporting private / public keys in a JWKS (JSON Web Key Set)
- [] Support for x5u, x5c, x5t, x5t#S256 parameters in a JWK
- [] Support deserialization of JWKs
- [] Support for combinations of key operation parameters
- [] Follow RFC7517 security conciderations guidelines 

### Documentation 
- [] Describe how to run tests (Test section)

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
