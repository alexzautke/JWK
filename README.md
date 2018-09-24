# C# JWKs - JSON Web Keys (RFC7517)
This repository provides an implementation in C# of RFC7517 (JSON Web Keys).

`Notice: The current implementation has not been used in a production environment.<br>Here be dragons. Please fill any bugs you may find.`

## Getting Started

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key.

All details of the implementation are based on the following literature:
* [RFC 7517 - JSON Web Keys](https://www.rfc-editor.org/rfc/rfc7517)
* [RFC 7518 - JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518.txt)

Supported Key Types for creating new JWKs:

|                | Support |
|----------------|:-------------------------------|
| RSA            | :x:                             |
| Eliptic Curves | :negative_squared_cross_mark:   |
| HMAC           | :x:                             |
| AES            | :x:                             |
| None           | :x:                             |

|                               | Meaning |
|-------------------------------|:-------------                         |
| :white_check_mark:            | Fully Implemented and tested           |
| :negative_squared_cross_mark: | Currently being implemented / Untested |
| :x:                           | Not implemented yet                    |

## Build dependencies

The following configuration has been succesfully tested for building and running the project:
* Visual Studio for Mac - Version 7.6.6
* .Net Core - Version 2.1

## Limitations

### Project TODOs
- [] Complete support for all JWK Key Types
- [] Support for exporting private / public keys in a JWKS (JSON Web Key Set)

### Documentation 
- [] Describe how to run tests (Test section)
- [] Document Security Conciderations (Security Conciderations section)
- [] Description of how to use the project as a library (INSTALL section)
- [] Continuous Integration and Build Status (Build dependencies section)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details 
