namespace CreativeCode.JWK
{
    /// <summary>
    /// Helpers for the big endian unsigned integers which RSA and elliptic curve key parameters are made of.
    /// </summary>
    internal static class UnsignedInteger
    {
        /// <summary>
        /// The bit length of a big endian unsigned integer. BitOperations.LeadingZeroCount is not available on
        /// netstandard2.0.
        /// </summary>
        internal static int BitLength(byte[] bigEndianUnsigned)
        {
            var firstNonZero = 0;
            while (firstNonZero < bigEndianUnsigned.Length && bigEndianUnsigned[firstNonZero] == 0x00)
                firstNonZero++;

            if (firstNonZero == bigEndianUnsigned.Length)
                return 0;

            var bitLength = (bigEndianUnsigned.Length - firstNonZero - 1) * 8;
            for (var octet = bigEndianUnsigned[firstNonZero]; octet != 0; octet >>= 1)
                bitLength++;

            return bitLength;
        }
    }
}
