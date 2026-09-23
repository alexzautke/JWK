using System;
using CreativeCode.JWK.TypeConverters;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK.KeyParts
{
    // See RFC 7517 - JSON Web Key (JWK) - Section 4.2. "use" (Public Key Use) Parameters
    public sealed class PublicKeyUse : IJWKConverter
    {
        private const string SIG_VALUE = "sig";
        private const string ENC_VALUE = "enc";

        public static readonly PublicKeyUse Signature = new PublicKeyUse(SIG_VALUE);
        public static readonly PublicKeyUse Encryption = new PublicKeyUse(ENC_VALUE);

        public string KeyUse;

        private PublicKeyUse() { } // Used only for deserialization

        private PublicKeyUse(string keyUse)
        {
            this.KeyUse = keyUse;
        }

        public static PublicKeyUse TryGetPublicKeyUse(string publicKeyUse)
        {
            return publicKeyUse?.ToString() switch
            {
                SIG_VALUE => Signature,
                ENC_VALUE => Encryption,
                _ => null
            };
        }

        object IJWKConverter.Deserialize(JToken jwkRepresentation)
        {
            if (jwkRepresentation is null)
                return null;

            return TryGetPublicKeyUse(jwkRepresentation?.ToString());
        }

        object IJWKConverter.Deserialize(JObject jwkRepresentation)
        {
            throw new NotImplementedException();
        }

        string IJWKConverter.Serialize(KeyMembers members, object propertyValue)
        {
            return KeyUse;
        }
    }
}
