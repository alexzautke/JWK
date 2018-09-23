using System.ComponentModel;
using JWK.TypeConverters;

namespace JWK.Contants
{
    // See RFC 7518 - JSON Web Algorithms (JWA) - Section 4.4. "alg" (Algorithm) Parameter
    [TypeConverter(typeof(ConstantConverter))]
    public sealed class Algorithm
    {

        // HMAC
        public static readonly Algorithm HS256 = new Algorithm("HS256", KeyType.OctetSequence);
        public static readonly Algorithm HS384 = new Algorithm("HS384", KeyType.OctetSequence);
        public static readonly Algorithm HS512 = new Algorithm("HS512", KeyType.OctetSequence);

        // RSA
        public static readonly Algorithm RS256 = new Algorithm("RS256", KeyType.RSA);
        public static readonly Algorithm RS384 = new Algorithm("RS384", KeyType.RSA);
        public static readonly Algorithm RS512 = new Algorithm("RS512", KeyType.RSA);

        // Elliptic Curve
        public static readonly Algorithm ES256 = new Algorithm("ES256", KeyType.EllipticCurve);
        public static readonly Algorithm ES384 = new Algorithm("ES384", KeyType.EllipticCurve);
        public static readonly Algorithm ES512 = new Algorithm("ES512", KeyType.EllipticCurve);

        // AES
        public static readonly Algorithm A128GCM = new Algorithm("A128GCM", KeyType.OctetSequence);
        public static readonly Algorithm A256GCM = new Algorithm("A256GCM", KeyType.OctetSequence);

        // None
        public static readonly Algorithm None = new Algorithm("none", KeyType.OctetSequence);

        private readonly string value;
        public readonly KeyType keyType;

        private Algorithm(string value, KeyType keyType)
        {
            this.value = value;
            this.keyType = keyType;
        }

        public override string ToString()
        {
            return value;
        }
    }
}
