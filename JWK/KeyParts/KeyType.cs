using System;

namespace CreativeCode.JWK.KeyParts
{
    // See RFC 7518 - JSON Web Algorithms (JWA) - Section 6.1. "kty" (Key Type) Parameter Values
    public sealed class KeyType : IJWKKeyPart
    {
        private const string EC_VALUE = "EC";
        private const string RSA_VALUE = "RSA";
        private const string OCT_VALUE = "OCT";

        public static readonly KeyType EllipticCurve = new KeyType(EC_VALUE);
        public static readonly KeyType RSA = new KeyType(RSA_VALUE);
        public static readonly KeyType OCT = new KeyType(OCT_VALUE);

        public string Type;

        private KeyType(string type)
        {
            this.Type = type;
        }

        public string Serialize(bool shouldExportPrivateKey = false)
        {
            return Type;
        }
    }
}
