using System;
using CreativeCode.JWK.TypeConverters;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK.KeyParts
{
    /* See RFC 7518 - JSON Web Algorithms (JWA) 
       - Section 7.1. JSON Web Signature and Encryption Algorithms Registry
       - Section 3.1.  "alg" (Algorithm) Header Parameter Values for JWS      
    */
    public sealed class Algorithm : IJWKConverter
    {
        // HMAC
        private const string HS256_VALUE = "HS256";
        private const string HS384_VALUE = "HS384";
        private const string HS512_VALUE = "HS512";
        public static readonly Algorithm HS256 = new Algorithm(HS256_VALUE, true);
        public static readonly Algorithm HS384 = new Algorithm(HS384_VALUE, true);
        public static readonly Algorithm HS512 = new Algorithm(HS512_VALUE, true);

        // RSA
        private const string RS256_VALUE = "RS256";
        private const string RS384_VALUE = "RS384";
        private const string RS512_VALUE = "RS512";
        public static readonly Algorithm RS256 = new Algorithm(RS256_VALUE, false);
        public static readonly Algorithm RS384 = new Algorithm(RS384_VALUE, false);
        public static readonly Algorithm RS512 = new Algorithm(RS512_VALUE, false);

        // RSASSA-PSS. Creating a new key for these algorithms is not supported, but they are recognized when read.
        private const string PS256_VALUE = "PS256";
        private const string PS384_VALUE = "PS384";
        private const string PS512_VALUE = "PS512";
        public static readonly Algorithm PS256 = new Algorithm(PS256_VALUE, false);
        public static readonly Algorithm PS384 = new Algorithm(PS384_VALUE, false);
        public static readonly Algorithm PS512 = new Algorithm(PS512_VALUE, false);

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

        /// <summary>
        /// False if this algorithm is not one of the algorithms known to this library. The "alg" value is still
        /// preserved (and exported again) so that a JWK is not silently altered by a round trip.
        /// </summary>
        public bool IsRecognized { get; }

        private Algorithm() { } // Used only for deserialization

        private Algorithm(string name, bool isSymetric) : this(name, isSymetric, true) { }

        private Algorithm(string name, bool isSymetric, bool isRecognized)
        {
            Name = name;
            IsSymetric = isSymetric;
            IsRecognized = isRecognized;
        }

        /// <summary>
        /// Returns the algorithm with the given name. An algorithm which is not known to this library is returned as
        /// an instance with <see cref="IsRecognized"/> set to false instead of null, so that the "alg" value of a JWK
        /// survives deserialization and export. Returns null only if <paramref name="algorithm"/> is null or empty.
        /// </summary>
        /// <remarks>
        /// Up to and including 0.7.1 an unknown name returned null. A caller which rejects an algorithm by checking the
        /// result for null has to check <see cref="IsRecognized"/> instead, or it accepts any algorithm name.
        /// </remarks>
        public static Algorithm TryGetAlgorithm(string algorithm)
        {
            return algorithm switch
            {
                HS256_VALUE => HS256,
                HS384_VALUE => HS384,
                HS512_VALUE => HS512,

                RS256_VALUE => RS256,
                RS384_VALUE => RS384,
                RS512_VALUE => RS512,

                PS256_VALUE => PS256,
                PS384_VALUE => PS384,
                PS512_VALUE => PS512,

                ES256_VALUE => ES256,
                ES384_VALUE => ES384,
                ES512_VALUE => ES512,

                A128GCMKW_VALUE => A128GCMKW,
                A192GCMKW_VALUE => A192GCMKW,
                A256GCMKW_VALUE => A256GCMKW,

                NONE_VALUE => None,

                null => null,
                "" => null,

                _ => new Algorithm(algorithm, false, false)
            };
        }

        string IJWKConverter.Serialize(KeyMembers members, object propertyValue)
        {
            return Name;
        }

        object IJWKConverter.Deserialize(JToken jwkRepresentation)
        {
            if (jwkRepresentation is null)
                return null;

            return TryGetAlgorithm(jwkRepresentation.ToString());
        }

        object IJWKConverter.Deserialize(JObject jwkRepresentation)
        {
            throw new NotImplementedException();
        }

        public override bool Equals(object obj)
        {
            return obj is Algorithm other && Name == other.Name;
        }

        public override int GetHashCode()
        {
            return Name is null ? 0 : Name.GetHashCode();
        }

        public override string ToString()
        {
            return Name;
        }
    }
}
