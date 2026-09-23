using System;

namespace CreativeCode.JWK
{
    /// <summary>
    /// See https://tools.ietf.org/html/rfc7515#appendix-C
    /// </summary>
    public static class Base64Helper
    {
        public static string Base64urlEncode(byte[] s)
        {
            if (s == null)
                return String.Empty;
            
            string base64 = Convert.ToBase64String(s); // Regular base64 encoder
            base64 = base64.Split('=')[0]; // Remove any trailing '='s
            base64 = base64.Replace('+', '-');
            base64 = base64.Replace('/', '_');
            return base64;
        }
        
        /// <summary>
        /// Encode a big endian unsigned integer as a Base64urlUInt. Leading zero octets are dropped, because the
        /// representation "MUST utilize the minimum number of octets needed to represent the value"
        /// (See https://www.rfc-editor.org/rfc/rfc7518#section-2).
        /// </summary>
        public static string Base64urlEncodeUInt(byte[] s)
        {
            if (s == null)
                return string.Empty;

            var firstNonZero = 0;
            while (firstNonZero < s.Length - 1 && s[firstNonZero] == 0x00)
                firstNonZero++;

            if (firstNonZero == 0)
                return Base64urlEncode(s);

            var minimal = new byte[s.Length - firstNonZero];
            Array.Copy(s, firstNonZero, minimal, 0, minimal.Length);

            return Base64urlEncode(minimal);
        }

        public static byte[] Base64urlDecode(string arg)
        {
            if (!TryBase64urlDecode(arg, out var decoded))
                throw new FormatException("Illegal base64url string!");

            return decoded;
        }

        /// <summary>
        /// Decode a base64url encoded string without throwing. Unlike <see cref="Base64urlDecode"/> this also
        /// rejects input which is not part of the base64url alphabet (e.g. standard base64 padding or whitespace).
        /// </summary>
        public static bool TryBase64urlDecode(string arg, out byte[] decoded)
        {
            decoded = null;
            if (arg is null)
                return false;

            foreach (var c in arg)
            {
                var isBase64urlCharacter = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
                if (!isBase64urlCharacter)
                    return false;
            }

            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default:
                    return false; // A length of 1 modulo 4 cannot be produced by any base64 encoder
            }

            try
            {
                decoded = Convert.FromBase64String(s); // Standard base64 decoder
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }
}
