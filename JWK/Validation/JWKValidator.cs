using System;
using System.Collections.Generic;
using System.Linq;
using CreativeCode.JWK.KeyParts;
using Newtonsoft.Json.Linq;
using static CreativeCode.JWK.Base64Helper;

namespace CreativeCode.JWK.Validation
{
    /// <summary>
    /// Checks whether a JWK is a well formed key according to RFC 7517 and RFC 7518. This covers the structure of the
    /// JSON representation and the validity of the key material itself. It deliberately does not cover any policy a
    /// consumer may have about which keys it is willing to accept - which algorithms are allowed, whether a "kid" is
    /// required, or which key sizes are considered strong enough.
    /// </summary>
    internal static class JWKValidator
    {
        /// <summary>
        /// Checks which can only be made on the JSON representation, because the information is lost once the members
        /// have been turned into the parts of a JWK.
        /// </summary>
        internal static List<string> ValidateRepresentation(JObject jwkRepresentation)
        {
            var errors = new List<string>();

            if (!jwkRepresentation.TryGetValue("kty", out var keyTypeToken))
            {
                errors.Add("The key type ('kty') is missing. It is a mandatory element and MUST be present.");
                return errors; // Without a key type none of the remaining members can be interpreted
            }

            if (keyTypeToken.Type != JTokenType.String)
            {
                errors.Add("The key type ('kty') MUST be a JSON string.");
                return errors;
            }

            var keyType = KeyType.TryGetKeyType(keyTypeToken.ToString());
            if (keyType is null)
            {
                errors.Add($"The key type '{keyTypeToken}' is not supported.");
                return errors;
            }

            if (jwkRepresentation.TryGetValue("alg", out var algorithmToken) && algorithmToken.Type != JTokenType.String)
                errors.Add("The algorithm ('alg') MUST be a JSON string.");

            if (jwkRepresentation.TryGetValue("kid", out var keyIdToken) && keyIdToken.Type != JTokenType.String)
                errors.Add("The key id ('kid') MUST be a JSON string.");

            if (jwkRepresentation.TryGetValue("use", out var publicKeyUseToken) && publicKeyUseToken.Type != JTokenType.String)
                errors.Add("The public key use ('use') MUST be a JSON string.");

            // See RFC 7517 - Section 4.3: an array of key operation values, which are strings
            if (jwkRepresentation.TryGetValue("key_ops", out var keyOperationsToken))
            {
                if (!(keyOperationsToken is JArray keyOperationTokens))
                    errors.Add("The key operations ('key_ops') MUST be a JSON array.");
                else if (keyOperationTokens.Any(keyOperation => keyOperation.Type != JTokenType.String))
                    errors.Add("Every entry of the key operations ('key_ops') MUST be a JSON string.");
                else
                {
                    // "Duplicate key operation values MUST NOT be present in the array". Values are case-sensitive.
                    var duplicates = keyOperationTokens
                        .Select(keyOperation => keyOperation.ToString())
                        .GroupBy(keyOperation => keyOperation, StringComparer.Ordinal)
                        .Where(group => group.Count() > 1);
                    foreach (var duplicate in duplicates)
                        errors.Add($"The key operations ('key_ops') contain '{duplicate.Key}' more than once. Duplicate key operation values MUST NOT be present.");
                }
            }

            foreach (var parameter in KeyParameter.ParametersFor(keyType))
            {
                if (parameter.Encoding == KeyParameterEncoding.Json)
                    continue; // "oth" is an array, not a string

                if (jwkRepresentation.TryGetValue(parameter.Name, out var parameterToken) && parameterToken.Type != JTokenType.String)
                    errors.Add($"The key parameter '{parameter.Name}' MUST be a JSON string.");
            }

            return errors;
        }

        /// <summary>
        /// Checks the key material of a JWK: that the parameters required for its key type are present, that they are
        /// encoded as RFC 7518 requires, and - for an elliptic curve key - that the public key really is a point on
        /// the curve it claims.
        /// </summary>
        internal static List<string> ValidateKey(JWK jwk)
        {
            var errors = new List<string>();

            if (jwk.KeyType is null)
            {
                errors.Add("The key type ('kty') is missing or not supported.");
                return errors;
            }

            var keyParameters = jwk.KeyParameters ?? new Dictionary<KeyParameter, string>();

            foreach (var required in KeyParameter.RequiredParametersFor(jwk.KeyType))
            {
                if (!keyParameters.ContainsKey(required) || string.IsNullOrEmpty(keyParameters[required]))
                    errors.Add($"The key parameter '{required.Name}' is missing. It is mandatory for a key of type '{jwk.KeyType}'.");
            }

            foreach (var keyParameter in keyParameters)
            {
                if (keyParameter.Key.Encoding == KeyParameterEncoding.Text || keyParameter.Key.Encoding == KeyParameterEncoding.Json)
                    continue;
                if (string.IsNullOrEmpty(keyParameter.Value))
                    continue; // Already reported if the parameter is mandatory

                if (!TryBase64urlDecode(keyParameter.Value, out var decoded))
                {
                    errors.Add($"The key parameter '{keyParameter.Key.Name}' is not a valid base64url encoded value.");
                    continue;
                }

                if (decoded.Length == 0)
                {
                    errors.Add($"The key parameter '{keyParameter.Key.Name}' is empty.");
                    continue;
                }

                // See RFC 7518 - Section 2. Base64urlUInt: "The representation MUST NOT have any leading zero octets"
                if (keyParameter.Key.Encoding == KeyParameterEncoding.Base64urlUInt && decoded[0] == 0x00)
                    errors.Add($"The key parameter '{keyParameter.Key.Name}' has a leading zero octet. A Base64urlUInt value MUST use the minimum number of octets needed to represent its value.");
            }

            if (jwk.KeyType == KeyType.EllipticCurve)
                errors.AddRange(ValidateEllipticCurveKey(keyParameters));
            if (jwk.KeyType == KeyType.RSA)
                errors.AddRange(ValidateRSAPrivateKey(keyParameters));

            return errors;
        }

        /// <summary>
        /// See RFC 7518 - Section 6.3.2: a private RSA key may carry only "d", but if any of the other private key
        /// parameters is present, then all of them MUST be present.
        /// </summary>
        private static List<string> ValidateRSAPrivateKey(IDictionary<KeyParameter, string> keyParameters)
        {
            var errors = new List<string>();
            var otherPrivateParameters = new[] { KeyParameter.RSAKeyParameterP, KeyParameter.RSAKeyParameterQ, KeyParameter.RSAKeyParameterDP, KeyParameter.RSAKeyParameterDQ, KeyParameter.RSAKeyParameterQI };

            var missing = otherPrivateParameters.Where(parameter => !keyParameters.ContainsKey(parameter) || string.IsNullOrEmpty(keyParameters[parameter])).ToList();
            if (missing.Count == 0 || missing.Count == otherPrivateParameters.Length)
                return errors;

            errors.Add($"The private RSA key is incomplete. The key parameters '{string.Join("', '", missing.Select(parameter => parameter.Name))}' are missing.");

            return errors;
        }

        private static List<string> ValidateEllipticCurveKey(IDictionary<KeyParameter, string> keyParameters)
        {
            var errors = new List<string>();

            keyParameters.TryGetValue(KeyParameter.ECKeyParameterCRV, out var curveName);
            if (string.IsNullOrEmpty(curveName))
                return errors; // Already reported as a missing mandatory parameter

            var curve = EllipticCurve.TryGetCurve(curveName);
            if (curve is null)
            {
                errors.Add($"The curve '{curveName}' is not supported.");
                return errors;
            }

            var coordinates = new Dictionary<KeyParameter, byte[]>();
            foreach (var parameter in new[] { KeyParameter.ECKeyParameterX, KeyParameter.ECKeyParameterY, KeyParameter.ECKeyParameterD })
            {
                if (!keyParameters.TryGetValue(parameter, out var value) || string.IsNullOrEmpty(value))
                    continue;
                if (!TryBase64urlDecode(value, out var decoded))
                    continue; // Already reported as an invalid base64url value

                // See RFC 7518 - Section 6.2.1.2: the octet sequence MUST be the full size of a coordinate, left padded with zeros
                if (decoded.Length != curve.CoordinateLength)
                    errors.Add($"The key parameter '{parameter.Name}' is {decoded.Length} octets long, but curve '{curve.Name}' requires exactly {curve.CoordinateLength} octets.");
                else
                    coordinates.Add(parameter, decoded);
            }

            if (coordinates.ContainsKey(KeyParameter.ECKeyParameterX) && coordinates.ContainsKey(KeyParameter.ECKeyParameterY)
                && !curve.IsPointOnCurve(coordinates[KeyParameter.ECKeyParameterX], coordinates[KeyParameter.ECKeyParameterY]))
            {
                errors.Add($"The public key ('x', 'y') is not a point on curve '{curve.Name}'.");
            }

            return errors;
        }

        /// <summary>
        /// The bit length of a big endian unsigned integer. BitOperations.LeadingZeroCount is not available on
        /// netstandard2.0.
        /// </summary>
        internal static int BitLength(byte[] bigEndianUnsigned)
        {
            var firstNonZero = 0;
            while (firstNonZero < bigEndianUnsigned.Length && bigEndianUnsigned[firstNonZero] == 0x00)
                firstNonZero++;

            if (firstNonZero == bigEndianUnsigned.Length)
                return 0;

            var bitLength = (bigEndianUnsigned.Length - firstNonZero - 1) * 8;
            for (var octet = bigEndianUnsigned[firstNonZero]; octet != 0; octet >>= 1)
                bitLength++;

            return bitLength;
        }
    }
}
