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
        private const string OCT_VALUE = "OCT";

        public static readonly KeyType EllipticCurve = new KeyType(EC_VALUE);
        public static readonly KeyType RSA = new KeyType(RSA_VALUE);
        public static readonly KeyType OCT = new KeyType(OCT_VALUE);

        public string Type;

        private KeyType() { } // Used only for deserialization

        private KeyType(string type)
        {
            this.Type = type;
        }

        public object Deserialize(JToken jwkRepresentation)
        {
            if (jwkRepresentation is null)
                throw new NotSupportedException("Cannot deserialize null value");

            return jwkRepresentation.ToString() switch
            {
                EC_VALUE => EllipticCurve,
                RSA_VALUE => RSA,
                OCT_VALUE => OCT,
                _ => null
            };
        }

        public object Deserialize(JObject jwkRepresentation)
        {
            throw new NotImplementedException();
        }

        public string Serialize(bool shouldExportPrivateKey = false, object propertyValue = null)
        {
            return Type;
        }
    }
}
