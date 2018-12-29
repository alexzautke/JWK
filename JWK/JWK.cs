using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using CreativeCode.JWK.KeyParts;
using CreativeCode.JWK.TypeConverters;

namespace CreativeCode.JWK
{
    [JsonConverter(typeof(JWKConverter))]
    public class JWK
    {
        [JsonProperty(PropertyName = "kty")]
        public KeyType KeyType { get; private set; }             // REQUIRED

        [JsonProperty(PropertyName = "use")]
        public PublicKeyUse PublicKeyUse { get; private set; }   // OPTIONAL

        [JsonProperty(PropertyName = "key_ops")]
        public KeyOperations KeyOperations { get; private set; } // OPTIONAL

        [JsonProperty(PropertyName = "alg")]
        public Algorithm Algorithm { get; private set; }         // OPTIONAL

        [JsonProperty(PropertyName = "kid")]
        public Guid KeyID { get; private set; }                  // OPTIONAL

        [JsonProperty]
        public KeyParameters keyParameters { get; private set; } // OPTIONAL

        internal bool _shouldExportPrivateKey;

        public void BuildWithOptions(PublicKeyUse publicKeyUse, KeyOperations keyOperations, Algorithm algorithm)
        {
            #if DEBUG
                var performanceStopWatch = new Stopwatch();
                performanceStopWatch.Start();
            #endif

            PublicKeyUse = publicKeyUse;
            KeyOperations = keyOperations;
            Algorithm = algorithm;
            KeyID = Guid.NewGuid();
            KeyType = algorithm.KeyType;

            if(algorithm.KeyType.Equals(KeyType.EllipticCurve)){
                ECParameters();
            }
            else if(algorithm.KeyType.Equals(KeyType.RSA)){
                RSAParameters();
            }
            else if (algorithm.KeyType.Equals(KeyType.HMAC))
            {
                HMACParameters();
            }
            else if (algorithm.KeyType.Equals(KeyType.AES))
            {
                AESParameters();
            }
            else
            {
                NONEParameters();
            }

            #if DEBUG
                performanceStopWatch.Stop();
                Console.WriteLine("Debug Information - JWK - New JWK build was successfully. It took " + performanceStopWatch.Elapsed.TotalMilliseconds + "ms.");
            #endif
        }

        public string Export(bool shouldExportPrivateKey = false)
        {
            #if DEBUG
                var performanceStopWatch = new Stopwatch();
                performanceStopWatch.Start();
            #endif

            _shouldExportPrivateKey = shouldExportPrivateKey;

            if (shouldExportPrivateKey && IsSymmetric())
                throw new CryptographicException("Symetric key of type " + KeyType.Serialize() + " cannot be exported with shouldExportPrivateKey set to false.");

            var jwkJSON = JsonConvert.SerializeObject(this);

            #if DEBUG
                performanceStopWatch.Stop();
                Console.WriteLine("Debug Information - JWK - Serialized JWK. It took " + performanceStopWatch.Elapsed.TotalMilliseconds + "ms.");
            #endif

            return jwkJSON;
        }

        #region Create digital keys

        private void ECParameters()
        {
            ECDsa eCDsa = ECDsa.Create();
            var keyLength = Algorithm.Serialize().Split("ES")[1]; // Algorithm = 'ES' + Keylength
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
                default:
                    throw new ArgumentException("Could not create ECCurve based on algorithm: " + Algorithm);
            }
            eCDsa.GenerateKey(ECCurve.CreateFromOid(curveOid));

            ECParameters eCParameters = eCDsa.ExportParameters(true);
            var privateKeyD = Base64urlEncode(eCParameters.D);
            var publicKeyX = Base64urlEncode(eCParameters.Q.X);
            var publicKeyY = Base64urlEncode(eCParameters.Q.Y);

            keyParameters = new KeyParameters(new Dictionary<string, (string parameterValue, bool isPrivate)>
            {
                {"crv", (curveName, false)},
                {"x", (publicKeyX, false)},
                {"y", (publicKeyY, false)},
                {"d", (privateKeyD, true)}
            });
        }

        private void RSAParameters()
        {
            const int rsaKeySize = 2056; // See recommendations: https://www.keylength.com/en/compare/
            using (var rsaKey = new RSACryptoServiceProvider(rsaKeySize)){

                var rsaKeyParameters = rsaKey.ExportParameters(true);

                // RSAParameters properties are big-endian, no need to reverse the byte array (See RFC7518 - 6.3.1. Parameters for RSA Public Keys)
                var modulus = Base64urlEncode(rsaKeyParameters.Modulus);
                var exponent = Base64urlEncode(rsaKeyParameters.Exponent);
                var privateExponent = Base64urlEncode(rsaKeyParameters.D);

                keyParameters = new KeyParameters(new Dictionary<string, (string parameterValue, bool isPrivate)>
                {
                    {"n", (modulus, false)},
                    {"e", (exponent, false)},
                    {"d", (privateExponent, true)}
                });
            }
        }

        private void HMACParameters()
        {
            // Key size is selected based on https://tools.ietf.org/html/rfc2104#section-3
            Regex keySizeRegex = new Regex(@"(?<shaVersion>[1-9]+)", RegexOptions.Compiled);
            var matches = keySizeRegex.Match(Algorithm.Serialize());
            var shaVersionFromAlgorithmName = matches.Groups["shaVersion"].Value;

            HMAC hmac;
            switch (shaVersionFromAlgorithmName){
                case "256":
                    hmac = new HMACSHA256(CreateHMACKey(64));
                    break;
                case "384":
                    hmac = new HMACSHA384(CreateHMACKey(128));
                    break;
                case "512":
                    hmac = new HMACSHA512(CreateHMACKey(128));
                    break;
                default:
                    throw new CryptographicException("Could not create HMAC key based on algorithm " + Algorithm + " (Could not parse expected SHA version)");
            }

            var key = Base64urlEncode(hmac.Key);
            keyParameters = new KeyParameters(new Dictionary<string, (string parameterValue, bool isPrivate)>
            {
                {"k", (key, true)}
            });
        }

        private byte[] CreateHMACKey(int keySize){
            byte[] key = new byte[keySize];
            var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            rngCryptoServiceProvider.GetBytes(key);
            return key;
        }

        private void AESParameters()
        {
            var aesKey = Aes.Create();

            Regex keySizeRegex = new Regex(@"(?<keySize>[1-9]+)", RegexOptions.Compiled);
            var matches = keySizeRegex.Match(Algorithm.Serialize());
            var aesKeySizeFromAlgorithmName = matches.Groups["keySize"].Value;
            var aesKeySize = int.Parse(aesKeySizeFromAlgorithmName);
            if(!aesKey.ValidKeySize(aesKeySize)) {
                throw new CryptographicException("Could not create AES key based on algorithm " + Algorithm + " (Could not parse expected AES key size)");
            }
            aesKey.KeySize = aesKeySize;
            aesKey.GenerateKey();

            var key = Base64urlEncode(aesKey.Key);
            keyParameters = new KeyParameters(new Dictionary<string, (string parameterValue, bool isPrivate)>
            {
                {"k", (key, true)}
            });
        }

        private void NONEParameters()
        {
            keyParameters = null;
        }

        #endregion Create digital keys

        #region Crypto helper methods

        public bool IsSymmetric()
        {
            return KeyType.Equals(KeyType.HMAC) || KeyType.Equals(KeyType.AES);
        }

        #endregion Crypto helper methods

        #region Helper methods

        private string Base64urlEncode(byte[] s)
        {
            if (s == null)
                return String.Empty;

            string base64 = Convert.ToBase64String(s); // Regular base64 encoder
            base64 = base64.Split('=')[0]; // Remove any trailing '='s
            base64 = base64.Replace('+', '-');
            base64 = base64.Replace('/', '_');
            return base64;
        }

        public override string ToString()
        {
            return Export(false);
        }

        #endregion Helper methods

    }

}
