using System;

namespace CreativeCode.JWK.KeyParts
{
    /* See RFC 7518 - JSON Web Algorithms (JWA) 
       - Section 7.1. JSON Web Signature and Encryption Algorithms Registry
       - Section 3.1.  "alg" (Algorithm) Header Parameter Values for JWS      
    */
    public sealed class Algorithm : IJWKKeyPart
    {
        // HMAC
        public static readonly Algorithm HS256 = new Algorithm("HS256", true);
        public static readonly Algorithm HS384 = new Algorithm("HS384", true);
        public static readonly Algorithm HS512 = new Algorithm("HS512", true);

        // RSA
        // Support for PS256, PS384, PS512 is not planned.
        public static readonly Algorithm RS256 = new Algorithm("RS256", false);
        public static readonly Algorithm RS384 = new Algorithm("RS384", false);
        public static readonly Algorithm RS512 = new Algorithm("RS512", false);

        // Elliptic Curve
        public static readonly Algorithm ES256 = new Algorithm("ES256", false);
        public static readonly Algorithm ES384 = new Algorithm("ES384", false);
        public static readonly Algorithm ES512 = new Algorithm("ES512", false);

        // AES
        public static readonly Algorithm A128GCMKW = new Algorithm("A128GCMKW", true);
        public static readonly Algorithm A192GCMKW = new Algorithm("A192GCMKW", true);
        public static readonly Algorithm A256GCMKW = new Algorithm("A256GCMKW", true);

        // None
        public static readonly Algorithm None = new Algorithm("none", false);

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
    }
}
