using System;
using System.Collections.Generic;

namespace CreativeCode.JWK.KeyParts
{
    /// <summary>
    /// How the value of a key parameter is encoded in its JSON representation.
    /// </summary>
    public enum KeyParameterEncoding
    {
        /// <summary>
        /// A base64url encoded big endian unsigned integer which MUST use the minimum number of octets needed to
        /// represent its value (See RFC 7518 - Section 2. "Base64urlUInt").
        /// </summary>
        Base64urlUInt,

        /// <summary>
        /// A base64url encoded octet string of a length fixed by the key (See RFC 7518 - Section 6.2.1.2).
        /// </summary>
        Base64urlOctets,

        /// <summary>
        /// A plain JSON string.
        /// </summary>
        Text,

        /// <summary>
        /// A JSON value which is not a string (currently only the array of the "oth" parameter).
        /// </summary>
        Json
    }

    public sealed class KeyParameter
    {
        public static readonly KeyParameter RSAKeyParameterN = new KeyParameter("n", false, KeyParameterEncoding.Base64urlUInt);
        public static readonly KeyParameter RSAKeyParameterE = new KeyParameter("e", false, KeyParameterEncoding.Base64urlUInt);
        public static readonly KeyParameter RSAKeyParameterD = new KeyParameter("d", true, KeyParameterEncoding.Base64urlUInt);
        public static readonly KeyParameter RSAKeyParameterP = new KeyParameter("p", true, KeyParameterEncoding.Base64urlUInt);
        public static readonly KeyParameter RSAKeyParameterQ = new KeyParameter("q", true, KeyParameterEncoding.Base64urlUInt);
        public static readonly KeyParameter RSAKeyParameterDP = new KeyParameter("dp", true, KeyParameterEncoding.Base64urlUInt);
        public static readonly KeyParameter RSAKeyParameterDQ = new KeyParameter("dq", true, KeyParameterEncoding.Base64urlUInt);
        public static readonly KeyParameter RSAKeyParameterQI = new KeyParameter("qi", true, KeyParameterEncoding.Base64urlUInt);
        public static readonly KeyParameter RSAKeyParameterOTH = new KeyParameter("oth", true, KeyParameterEncoding.Json);

        public static readonly IReadOnlyCollection<KeyParameter> RSAKeyParameters = new[] { RSAKeyParameterN, RSAKeyParameterE, RSAKeyParameterD, RSAKeyParameterP, RSAKeyParameterQ, RSAKeyParameterDP, RSAKeyParameterDQ, RSAKeyParameterQI, RSAKeyParameterOTH };

        public static readonly KeyParameter ECKeyParameterCRV = new KeyParameter("crv", false, KeyParameterEncoding.Text);
        public static readonly KeyParameter ECKeyParameterX = new KeyParameter("x", false, KeyParameterEncoding.Base64urlOctets);
        public static readonly KeyParameter ECKeyParameterY = new KeyParameter("y", false, KeyParameterEncoding.Base64urlOctets);
        public static readonly KeyParameter ECKeyParameterD = new KeyParameter("d", true, KeyParameterEncoding.Base64urlOctets);

        public static readonly IReadOnlyCollection<KeyParameter> ECKeyParameters = new[] { ECKeyParameterCRV, ECKeyParameterX, ECKeyParameterY, ECKeyParameterD };

        public static readonly KeyParameter OctKeyParameterK = new KeyParameter("k", true, KeyParameterEncoding.Base64urlOctets);

        public static readonly IReadOnlyCollection<KeyParameter> OctKeyParameters = new[] { OctKeyParameterK };

        private static readonly IReadOnlyCollection<KeyParameter> MandatoryRSAKeyParameters = new[] { RSAKeyParameterN, RSAKeyParameterE };
        private static readonly IReadOnlyCollection<KeyParameter> MandatoryECKeyParameters = new[] { ECKeyParameterCRV, ECKeyParameterX, ECKeyParameterY };
        private static readonly IReadOnlyCollection<KeyParameter> MandatoryOctKeyParameters = new[] { OctKeyParameterK };

        public string Name { get; }
        public bool IsPrivate { get; }
        public KeyParameterEncoding Encoding { get; }

        private KeyParameter(string name, bool isPrivate, KeyParameterEncoding encoding)
        {
            if (name == null)
                throw new ArgumentNullException("Name cannot be null");

            Name = name;
            IsPrivate = isPrivate;
            Encoding = encoding;
        }

        /// <summary>
        /// All key parameters defined for the given key type, or an empty list if the key type is not known.
        /// </summary>
        public static IReadOnlyCollection<KeyParameter> ParametersFor(KeyType keyType)
        {
            return keyType switch
            {
                _ when keyType == KeyType.RSA => RSAKeyParameters,
                _ when keyType == KeyType.EllipticCurve => ECKeyParameters,
                _ when keyType == KeyType.OCT => OctKeyParameters,
                _ => Array.Empty<KeyParameter>()
            };
        }

        /// <summary>
        /// The key parameters which MUST be present for the given key type. For a symmetric key this is the key
        /// material itself, as an "oct" key has no public parameters.
        /// </summary>
        public static IReadOnlyCollection<KeyParameter> RequiredParametersFor(KeyType keyType)
        {
            return keyType switch
            {
                _ when keyType == KeyType.RSA => MandatoryRSAKeyParameters,
                _ when keyType == KeyType.EllipticCurve => MandatoryECKeyParameters,
                _ when keyType == KeyType.OCT => MandatoryOctKeyParameters,
                _ => Array.Empty<KeyParameter>()
            };
        }

        public override string ToString()
        {
            return Name;
        }
    }
}
