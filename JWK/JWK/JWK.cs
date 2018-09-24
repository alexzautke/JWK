using System;
using Newtonsoft.Json;
using JWK.KeyParts;
using System.Security.Cryptography;

namespace JWK
{
    public class JWK
    {
        [JsonProperty(PropertyName = "kty")]
        private KeyType keyType;                // REQUIRED

        [JsonProperty(PropertyName = "use")]
        private PublicKeyUse publicKeyUse;      // OPTIONAL

        [JsonProperty(PropertyName = "key_ops")]
        private KeyOperations keyOperations;    // OPTIONAL

        [JsonProperty(PropertyName = "alg")]
        private Algorithm algorithm;            // OPTIONAL

        [JsonProperty(PropertyName = "kid")]
        private Guid keyID;                     // OPTIONAL

        public string JWKfromOptions(PublicKeyUse publicKeyUse, KeyOperations keyOperations, Algorithm algorithm)
        {
            this.publicKeyUse = publicKeyUse;
            this.keyOperations = keyOperations;
            this.algorithm = algorithm;
            this.keyID = Guid.NewGuid();
            this.keyType = algorithm.KeyType;

            if(algorithm.KeyType.Equals(KeyType.EllipticCurve)){
                throw new NotImplementedException("Elliptic Curve Key Parameters are not yet supported");
            }
            else if(algorithm.KeyType.Equals(KeyType.RSA)){
                throw new NotImplementedException("RSA Key Parameters are not yet supported");
            }
            else if (algorithm.KeyType.Equals(KeyType.HMAC))
            {
                throw new NotImplementedException("HMAC Key Parameters are not yet supported");
            }
            else if (algorithm.KeyType.Equals(KeyType.AES))
            {
                throw new NotImplementedException("AES Key Parameters are not yet supported");
            }
            else{
                throw new NotImplementedException("None Key Type is not yet supported");
            }

            return JsonConvert.SerializeObject(this);
        }

        private void ECAParameters()
        {

        }

        private void RSAParameters(){

        }

        private void HMACParameters()
        {

        }

        private void AESParameters()
        {

        }

        private void NONEParameters()
        {

        }

        private string Base64urlEncode(byte[] s)
        {
            string base64 = Convert.ToBase64String(s); // Regular base64 encoder
            base64 = base64.Split('=')[0]; // Remove any trailing '='s
            base64 = base64.Replace('+', '-');
            base64 = base64.Replace('/', '_');
            return base64;
        }

    }

}
