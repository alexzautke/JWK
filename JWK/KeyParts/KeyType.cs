using System.ComponentModel;
using CreativeCode.JWK.TypeConverters;

namespace CreativeCode.JWK.KeyParts
{
    // See RFC 7518 - JSON Web Algorithms (JWA) - Section 6.1. "kty" (Key Type) Parameter Values
    public sealed class KeyType : IJWKKeyPart
    {
        public static readonly KeyType EllipticCurve = new KeyType("EC");
        public static readonly KeyType RSA = new KeyType("RSA");
        public static readonly KeyType HMAC = new KeyType("oct");
        public static readonly KeyType AES = new KeyType("oct");
        public static readonly KeyType None = new KeyType("oct");

        private readonly string value;

        private KeyType(string value)
        {
            this.value = value;
        }

        public string Serialize()
        {
            return value;
        }
    }
}
