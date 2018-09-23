using System.ComponentModel;
using JWK.TypeConverters;

namespace JWK.Contants
{
    // See RFC 7518 - JSON Web Algorithms (JWA) - Section 6.1. "kty" (Key Type) Parameter Values
    [TypeConverter(typeof(ConstantConverter))]
    public sealed class KeyType
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

        public override string ToString()
        {
            return value;
        }
    }
}
