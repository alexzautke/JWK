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
                _ => null
            };
        }

        object IJWKConverter.Deserialize(JToken jwkRepresentation)
        {
            if (jwkRepresentation is null)
                throw new ArgumentNullException("Key Type is a mandatory element and MUST be present");

            return TryGetKeyType(jwkRepresentation?.ToString());
        }

        object IJWKConverter.Deserialize(JObject jwkRepresentation)
        {
            throw new NotImplementedException();
        }

        string IJWKConverter.Serialize(KeyMembers members, object propertyValue)
        {
            return Type;
        }

        public override string ToString()
        {
            return Type;
        }
    }
}
