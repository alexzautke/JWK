using System;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK.KeyParts
{
    /* See RFC 7518 - JSON Web Algorithms (JWA) 
       - Section 7.1. JSON Web Signature and Encryption Algorithms Registry
       - Section 3.1.  "alg" (Algorithm) Header Parameter Values for JWS      
    */
    public sealed class Algorithm : IJWKKeyPart
    {
        // HMAC
        private const string HS256_VALUE = "HS256";
        private const string HS384_VALUE = "HS384";
        private const string HS512_VALUE = "HS512";
        public static readonly Algorithm HS256 = new Algorithm(HS256_VALUE, true);
        public static readonly Algorithm HS384 = new Algorithm(HS384_VALUE, true);
        public static readonly Algorithm HS512 = new Algorithm(HS512_VALUE, true);

        // RSA
        // Support for PS256, PS384, PS512 is not planned.
        private const string RS256_VALUE = "RS256";
        private const string RS384_VALUE = "RS384";
        private const string RS512_VALUE = "RS512";
        public static readonly Algorithm RS256 = new Algorithm(RS256_VALUE, false);
        public static readonly Algorithm RS384 = new Algorithm(RS384_VALUE, false);
        public static readonly Algorithm RS512 = new Algorithm(RS512_VALUE, false);

        // Elliptic Curve
        private const string ES256_VALUE = "ES256";
        private const string ES384_VALUE = "ES384";
        private const string ES512_VALUE = "ES512";
        public static readonly Algorithm ES256 = new Algorithm(ES256_VALUE, false);
        public static readonly Algorithm ES384 = new Algorithm(ES384_VALUE, false);
        public static readonly Algorithm ES512 = new Algorithm(ES512_VALUE, false);

        // AES
        private const string A128GCMKW_VALUE = "A128GCMKW";
        private const string A192GCMKW_VALUE = "A192GCMKW";
        private const string A256GCMKW_VALUE = "A256GCMKW";
        public static readonly Algorithm A128GCMKW = new Algorithm(A128GCMKW_VALUE, true);
        public static readonly Algorithm A192GCMKW = new Algorithm(A192GCMKW_VALUE, true);
        public static readonly Algorithm A256GCMKW = new Algorithm(A256GCMKW_VALUE, true);

        // None
        private const string NONE_VALUE = "none";
        public static readonly Algorithm None = new Algorithm(NONE_VALUE, false);

        public string Name { get; }
        public bool IsSymetric { get; }

        private Algorithm() { } // Used only for deserialization

        private Algorithm(string name, bool isSymetric)
        {
            Name = name;
            IsSymetric = isSymetric;
        }

        public string Serialize(bool shouldExportPrivateKey = false)
        {
            return Name;
        }

        public object Deserialize(JToken jwkRepresentation)
        {
            if (jwkRepresentation is null)
                throw new NotSupportedException("Cannot deserialize null value");

            return jwkRepresentation.ToString() switch
            {
                HS256_VALUE => HS256,
                HS384_VALUE => HS384,
                HS512_VALUE => HS512,

                RS256_VALUE => RS256,
                RS384_VALUE => RS384,
                RS512_VALUE => RS512,

                ES256_VALUE => ES256,
                ES384_VALUE => ES384,
                ES512_VALUE => ES512,

                A128GCMKW_VALUE => A128GCMKW,
                A192GCMKW_VALUE => A192GCMKW_VALUE,
                A256GCMKW_VALUE => A256GCMKW_VALUE,

                NONE_VALUE => None,

                _ => null
            };
        }
    }
}
