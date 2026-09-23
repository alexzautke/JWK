using System;
using System.Numerics;
using System.Security.Cryptography;

namespace CreativeCode.JWK.KeyParts
{
    /// <summary>
    /// The curves registered for the "crv" parameter of an EC key.
    /// See RFC 7518 - JSON Web Algorithms (JWA) - Section 6.2.1.1. "crv" (Curve) Parameter
    /// </summary>
    public sealed class EllipticCurve
    {
        private const string P256_VALUE = "P-256";
        private const string P384_VALUE = "P-384";
        private const string P521_VALUE = "P-521";
        private const string P521_LEGACY_VALUE = "P-512"; // Name used by this library up to and including 0.7.1 for the curve of ES512

        // Domain parameters of the NIST prime curves. For all three, the curve is y^2 = x^3 - 3x + b over GF(p).
        private const string P256_PRIME = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
        private const string P256_B = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
        private const string P384_PRIME = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF";
        private const string P384_B = "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF";
        private const string P521_PRIME = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        private const string P521_B = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";

        // Workaround: Using ECCurve.CreateFromFriendlyName results in a PlatformException for NIST curves
        public static readonly EllipticCurve P256 = new EllipticCurve(P256_VALUE, "1.2.840.10045.3.1.7", 32, P256_PRIME, P256_B);
        public static readonly EllipticCurve P384 = new EllipticCurve(P384_VALUE, "1.3.132.0.34", 48, P384_PRIME, P384_B);
        public static readonly EllipticCurve P521 = new EllipticCurve(P521_VALUE, "1.3.132.0.35", 66, P521_PRIME, P521_B);

        /// <summary>
        /// The "crv" value of this curve.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The object identifier of this curve.
        /// </summary>
        public string Oid { get; }

        /// <summary>
        /// The number of octets of a single coordinate. The "x", "y" and "d" parameters of an EC key MUST be padded
        /// to exactly this length (See RFC 7518 - Section 6.2.1.2).
        /// </summary>
        public int CoordinateLength { get; }

        /// <summary>
        /// The size of this curve in bits.
        /// </summary>
        public int KeySizeInBits { get; }

        private readonly BigInteger _prime;
        private readonly BigInteger _b;

        private EllipticCurve(string name, string oid, int coordinateLength, string prime, string b)
        {
            Name = name;
            Oid = oid;
            CoordinateLength = coordinateLength;
            _prime = ParseHex(prime);
            _b = ParseHex(b);
            KeySizeInBits = (int)(_prime - 1).BitLength();
        }

        public static EllipticCurve TryGetCurve(string curve)
        {
            return curve switch
            {
                P256_VALUE => P256,
                P384_VALUE => P384,
                P521_VALUE => P521,
                P521_LEGACY_VALUE => P521,
                _ => null
            };
        }

        /// <summary>
        /// Returns the curve which the given algorithm ("ES256", "ES384", "ES512") is defined over, or null.
        /// See RFC 7518 - Section 3.4.
        /// </summary>
        public static EllipticCurve TryGetCurveForAlgorithm(Algorithm algorithm)
        {
            if (algorithm is null)
                return null;
            if (algorithm.Equals(Algorithm.ES256))
                return P256;
            if (algorithm.Equals(Algorithm.ES384))
                return P384;
            if (algorithm.Equals(Algorithm.ES512))
                return P521;

            return null;
        }

        public ECCurve ToECCurve()
        {
            return ECCurve.CreateFromOid(new Oid(Oid));
        }

        /// <summary>
        /// Determines whether the point (x, y) satisfies the curve equation y^2 = x^3 - 3x + b over GF(p).
        /// The point at infinity is not a valid public key and is rejected.
        /// </summary>
        public bool IsPointOnCurve(byte[] x, byte[] y)
        {
            if (x is null || y is null)
                return false;

            var pointX = ToBigInteger(x);
            var pointY = ToBigInteger(y);

            if (pointX < 0 || pointX >= _prime || pointY < 0 || pointY >= _prime)
                return false;
            if (pointX.IsZero && pointY.IsZero)
                return false;

            var left = BigInteger.Remainder(pointY * pointY, _prime);
            var right = BigInteger.Remainder(pointX * pointX * pointX - 3 * pointX + _b, _prime);
            if (right.Sign < 0)
                right += _prime;

            return left == right;
        }

        /// <summary>
        /// Reads a big-endian unsigned integer. BigInteger(byte[]) is little-endian and two's complement on
        /// netstandard2.0, so the octets are reversed and a zero octet is appended to keep the value positive.
        /// </summary>
        internal static BigInteger ToBigInteger(byte[] bigEndianUnsigned)
        {
            var littleEndian = new byte[bigEndianUnsigned.Length + 1];
            for (var i = 0; i < bigEndianUnsigned.Length; i++)
                littleEndian[i] = bigEndianUnsigned[bigEndianUnsigned.Length - 1 - i];

            return new BigInteger(littleEndian);
        }

        private static BigInteger ParseHex(string hex)
        {
            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);

            return ToBigInteger(bytes);
        }

        public override string ToString()
        {
            return Name;
        }
    }

    internal static class BigIntegerExtensions
    {
        /// <summary>
        /// BigInteger.GetBitLength is not available on netstandard2.0.
        /// </summary>
        internal static long BitLength(this BigInteger value)
        {
            long bitLength = 0;
            while (value > 0)
            {
                bitLength++;
                value >>= 1;
            }

            return bitLength;
        }
    }
}
