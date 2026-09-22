using System;
using CreativeCode.JWK.TypeConverters;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK.KeyParts
{
    // See RFC 7518 - JSON Web Algorithms (JWA) - Section 6.1. "kty" (Key Type) Parameter Values
    public sealed class KeyType : IJWKConverter
    {
        private const string EC_VALUE = "EC";
        private const string RSA_VALUE = "RSA";
        private const string OCT_VALUE = "oct";
        private const string OCT_LEGACY_VALUE = "OCT"; // Spelling used by this library up to and including 0.7.1

        public static readonly KeyType EllipticCurve = new KeyType(EC_VALUE);
        public static readonly KeyType RSA = new KeyType(RSA_VALUE);
        public static readonly KeyType OCT = new KeyType(OCT_VALUE);

        public string Type;

        private KeyType() { } // Used only for deserialization

        private KeyType(string type)
        {
            this.Type = type;
        }

        public static KeyType TryGetKeyType(string keyType)
        {
            return keyType?.ToString() switch
            {
                EC_VALUE => EllipticCurve,
                RSA_VALUE => RSA,
                OCT_VALUE => OCT,
                OCT_LEGACY_VALUE => OCT,
                _ => null
            };
        }

        public object Deserialize(JToken jwkRepresentation)
        {
            if (jwkRepresentation is null)
                throw new ArgumentNullException("Key Type is a mandatory element and MUST be present");

            return TryGetKeyType(jwkRepresentation?.ToString());
        }

        public object Deserialize(JObject jwkRepresentation)
        {
            throw new NotImplementedException();
        }

        public string Serialize(KeyMembers members = KeyMembers.Public, object propertyValue = null)
        {
            return Type;
        }

        public override string ToString()
        {
            return Type;
        }
    }
}
