using System;
using Newtonsoft.Json;
using JWK.KeyParts;
using System.Security.Cryptography;
using System.Collections.Generic;
using JWK.TypeConverters;
using System.Text.RegularExpressions;

namespace JWK
{
    [JsonConverter(typeof(JWKConverter))]
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

        [JsonProperty]
        private KeyParameters keyParameters;    // OPTIONAL

        public string JWKfromOptions(PublicKeyUse publicKeyUse, KeyOperations keyOperations, Algorithm algorithm)
        {
            this.publicKeyUse = publicKeyUse;
            this.keyOperations = keyOperations;
            this.algorithm = algorithm;
            this.keyID = Guid.NewGuid();
            this.keyType = algorithm.KeyType;

            if(algorithm.KeyType.Equals(KeyType.EllipticCurve)){
                ECParameters();
            }
            else if(algorithm.KeyType.Equals(KeyType.RSA)){
                RSAParameters();
            }
            else if (algorithm.KeyType.Equals(KeyType.HMAC))
            {
                HMACParameters();
                throw new NotImplementedException("HMAC Key Parameters are not yet supported");
            }
            else if (algorithm.KeyType.Equals(KeyType.AES))
            {
                AESParameters();
            }
            else
            {
                NONEParameters();
                throw new NotImplementedException("None Key Type is not yet supported");
            }

            return JsonConvert.SerializeObject(this);
        }

        // ToDo:
        //  - Check length of x,y,d parameter
        //  - Use a boolean to indicate if the private key should be exported

        private void ECParameters()
        {
            ECDsa eCDsa = ECDsa.Create();
            var keyLength = algorithm.ToString().Split("ES")[1]; // Algorithm = 'ES' + Keylength
            var curveName = "P-" + keyLength;
            Oid curveOid = null; // Workaround: Using ECCurve.CreateFromFriendlyName results in a PlatformException for NIST curves
            switch (keyLength)
            {
                case "256":
                    curveOid = new Oid("1.2.840.10045.3.1.7");
                    break;
                case "384":
                    curveOid = new Oid("1.3.132.0.34");
                    break;
                case "512":
                    curveOid = new Oid("1.3.132.0.35");
                    break;
            }
            eCDsa.GenerateKey(ECCurve.CreateFromOid(curveOid));

            ECParameters eCParameters = eCDsa.ExportParameters(true);
            var privateKeyD = Base64urlEncode(eCParameters.D);
            var publicKeyX = Base64urlEncode(eCParameters.Q.X);
            var publicKeyY = Base64urlEncode(eCParameters.Q.Y);

            keyParameters = new KeyParameters(new Dictionary<string, string>
            {
                {"crv", curveName},
                {"x", publicKeyX},
                {"y", publicKeyY},
                {"d", privateKeyD}
            });
        }

        // ToDo:
        //  - Improve Error Handling RSACryptoServiceProvider
        //  - Use a boolean to indicate if the private key should be exported

        private void RSAParameters()
        {
            const int rsaKeySize = 2056; // See recommendations: https://www.keylength.com/en/compare/
            using (var rsaKey = new RSACryptoServiceProvider(rsaKeySize)){

                var rsaKeyParameters = rsaKey.ExportParameters(true);

                // RSAParameters properties are big-endian, no need to reverse the byte array (See RFC7518 - 6.3.1. Parameters for RSA Public Keys)
                var modulus = Base64urlEncode(rsaKeyParameters.Modulus);
                var exponent = Base64urlEncode(rsaKeyParameters.Exponent);
                var privateExponent = Base64urlEncode(rsaKeyParameters.D);

                keyParameters = new KeyParameters(new Dictionary<string, string>
                {
                    {"n", modulus},
                    {"e", exponent},
                    {"d", privateExponent}
                });
            }
        }

        private void HMACParameters()
        {

        }

        // ToDo:
        //  - Improve Error Handling ValidKeySize

        private void AESParameters()
        {
            var aesKey = Aes.Create();

            Regex keySizeRegex = new Regex(@"(?<keySize>[1-9]+)", RegexOptions.Compiled);
            var matches = keySizeRegex.Match(algorithm.ToString());
            var aesKeySizeFromAlgorithmName = matches.Groups["keySize"].Value;
            var aesKeySize = int.Parse(aesKeySizeFromAlgorithmName);
            if(!aesKey.ValidKeySize(aesKeySize)) {
                // Throw exception
            }
            aesKey.KeySize = aesKeySize;

            aesKey.GenerateKey();

            keyParameters = new KeyParameters(new Dictionary<string, string>
            {
                {"k", Base64urlEncode(aesKey.Key)}
            });
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
