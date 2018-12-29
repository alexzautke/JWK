# CreativeCode.JWK Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

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