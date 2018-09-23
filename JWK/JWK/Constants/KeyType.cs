namespace JWK.Contants
{
    // See RFC 7518 - JSON Web Algorithms (JWA) - Section 6.1. "kty" (Key Type) Parameter Values
    public sealed class KeyType
    {
        public static readonly KeyType EllipticCurve = new KeyType(1, "EC");
        public static readonly KeyType RSA = new KeyType(2, "RSA");
        public static readonly KeyType OctetSequence = new KeyType(3, "oct");

        private readonly string value;
        private readonly int id;

        private KeyType(int id, string value)
        {
            this.id = id;
            this.value = value;
        }

        public override string ToString()
        {
            return value;
        }
    }
}
