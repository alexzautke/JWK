namespace JWK.Contants
{
    // See RFC 7518 - JSON Web Algorithms (JWA) - Section 4.4. "alg" (Algorithm) Parameter
    public sealed class Algorithm
    {

        // HMAC
        public static readonly Algorithm HS256 = new Algorithm(1, "HS256", KeyType.OctetSequence);
        public static readonly Algorithm HS384 = new Algorithm(1, "HS384", KeyType.OctetSequence);
        public static readonly Algorithm HS512 = new Algorithm(1, "HS512", KeyType.OctetSequence);

        // RSA
        public static readonly Algorithm RS256 = new Algorithm(1, "RS256", KeyType.RSA);
        public static readonly Algorithm RS384 = new Algorithm(1, "RS384", KeyType.RSA);
        public static readonly Algorithm RS512 = new Algorithm(1, "RS512", KeyType.RSA);

        // Elliptic Curve
        public static readonly Algorithm ES256 = new Algorithm(1, "ES256", KeyType.EllipticCurve);
        public static readonly Algorithm ES384 = new Algorithm(1, "ES384", KeyType.EllipticCurve);
        public static readonly Algorithm ES512 = new Algorithm(1, "ES512", KeyType.EllipticCurve);

        // AES
        public static readonly Algorithm A128GCM = new Algorithm(1, "A128GCM", KeyType.OctetSequence);
        public static readonly Algorithm A256GCM = new Algorithm(1, "A256GCM", KeyType.OctetSequence);

        // None
        public static readonly Algorithm None = new Algorithm(1, "none", KeyType.OctetSequence);

        private readonly string value;
        private readonly int id;
        public readonly KeyType keyType;

        private Algorithm(int id, string value, KeyType keyType)
        {
            this.id = id;
            this.value = value;
            this.keyType = keyType;
        }

        public override string ToString()
        {
            return value;
        }
    }
}
