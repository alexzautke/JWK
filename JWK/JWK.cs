using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using CreativeCode.JWK.KeyParts;
using CreativeCode.JWK.TypeConverters;
using System.Linq;

namespace CreativeCode.JWK
{
    [JsonConverter(typeof(JWKConverter))]
    public class JWK
    {
        [JsonProperty(PropertyName = "kty")]
        public KeyType KeyType { get; private set; }             // REQUIRED

        [JsonProperty(PropertyName = "use")]
        public PublicKeyUse PublicKeyUse { get; private set; }   // OPTIONAL

        [JsonProperty]
        public KeyOperations KeyOperations { get; private set; } // OPTIONAL

        [JsonProperty(PropertyName = "alg")]
        public Algorithm Algorithm { get; private set; }         // OPTIONAL

        [JsonProperty(PropertyName = "kid")]
        public Guid KeyID { get; private set; }                  // OPTIONAL

        [JsonProperty]
        public KeyParameters KeyParameters { get; private set; } // OPTIONAL

        internal bool _shouldExportPrivateKey;

        private JWK() { } // Used only for deserialization

        public JWK(string jwk)
        {
            JsonConvert.DeserializeObject<JWK>(jwk);
        }

        public JWK(PublicKeyUse publicKeyUse, KeyOperations keyOperations, Algorithm algorithm)
        {
            PublicKeyUse = publicKeyUse;
            KeyOperations = keyOperations;
            Algorithm = algorithm;
            KeyID = Guid.NewGuid();
            KeyType = DeriveKeyType(algorithm);

            InitializeKey();
        }

        private KeyType DeriveKeyType(Algorithm algorithm)
        {
            if (algorithm.IsSymetric)
                return KeyType.OCT;
            if (algorithm == Algorithm.RS256 || algorithm == Algorithm.RS384 || algorithm == Algorithm.RS512)
                return KeyType.RSA;
            if (algorithm == Algorithm.ES256 || algorithm == Algorithm.ES384 || algorithm == Algorithm.ES512)
                return KeyType.EllipticCurve;

            return null;
        }

        public JWK(PublicKeyUse publicKeyUse, KeyOperations keyOperations, Algorithm algorithm, KeyParameters keyParameters)
        {
            PublicKeyUse = publicKeyUse;
            KeyOperations = keyOperations;
            Algorithm = algorithm;
            KeyID = Guid.NewGuid();
            KeyType = DeriveKeyType(algorithm);
            KeyParameters = keyParameters;
        }

        private void InitializeKey()
        {
            #if DEBUG
                var performanceStopWatch = new Stopwatch();
                performanceStopWatch.Start();
            #endif

            var keyTypeIndication = Algorithm.Name.FirstOrDefault();
            switch (keyTypeIndication)
            {
                case 'H':
                    HMACParameters();
                    break;
                case 'R':
                    RSAParameters();
                    break;
                case 'A':
                    AESParameters();
                    break;
                case 'E':
                    ECParameters();
                    break;
                default:
                    NONEParameters();
                    break;
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

            if (!shouldExportPrivateKey && IsSymmetric())
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
            var keyLength = Algorithm.Serialize().Split(new string[] { "ES" }, StringSplitOptions.None)[1]; // Algorithm = 'ES' + Keylength
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
                    throw new ArgumentException("Could not create ECCurve based on algorithm: " + Algorithm.Serialize());
            }
            eCDsa.GenerateKey(ECCurve.CreateFromOid(curveOid));

            ECParameters eCParameters = eCDsa.ExportParameters(true);
            var privateKeyD = Base64urlEncode(eCParameters.D);
            var publicKeyX = Base64urlEncode(eCParameters.Q.X);
            var publicKeyY = Base64urlEncode(eCParameters.Q.Y);

            KeyParameters = new KeyParameters(new Dictionary<string, (string parameterValue, bool isPrivate)>
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
                var firstPrimeFactor = Base64urlEncode(rsaKeyParameters.P);
                var secondPrimeFactor = Base64urlEncode(rsaKeyParameters.Q);
                var firstFactorCRTExponent = Base64urlEncode(rsaKeyParameters.DP);
                var secondFactorCRTExponent = Base64urlEncode(rsaKeyParameters.DQ);
                var firstCRTCoefficient = Base64urlEncode(rsaKeyParameters.InverseQ);

                KeyParameters = new KeyParameters(new Dictionary<string, (string parameterValue, bool isPrivate)>
                {
                    {"n", (modulus, false)},
                    {"e", (exponent, false)},
                    {"d", (privateExponent, true)},
                    {"p", (firstPrimeFactor, true)},
                    {"q", (secondPrimeFactor, true)},
                    {"dp", (firstFactorCRTExponent, true)},
                    {"dq", (secondFactorCRTExponent, true)},
                    {"qi", (firstCRTCoefficient, true)}
                });
            }
        }

        private void HMACParameters()
        {
            /* Key size is selected based on NIST Special Publication 800-107 Revision 1 
               Recommendation for Applications Using Approved Hash Algorithms
               Section 5.3.4 Security Effect of the HMAC Key
            */           
            HMAC hmac;
            switch (Algorithm.Serialize()){
                case "HS256":
                    hmac = new HMACSHA256(CreateHMACKey(64));
                    break;
                case "HS384":
                    hmac = new HMACSHA384(CreateHMACKey(128));
                    break;
                case "HS512":
                    hmac = new HMACSHA512(CreateHMACKey(128));
                    break;
                default:
                    throw new CryptographicException("Could not create HMAC key based on algorithm " + Algorithm.Serialize() + " (Could not parse expected SHA version)");
            }

            var key = Base64urlEncode(hmac.Key);
            KeyParameters = new KeyParameters(new Dictionary<string, (string parameterValue, bool isPrivate)>
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
                throw new CryptographicException("Could not create AES key based on algorithm " + Algorithm.Serialize() + " (Could not parse expected AES key size)");
            }
            aesKey.KeySize = aesKeySize;
            aesKey.GenerateKey();

            var key = Base64urlEncode(aesKey.Key);
            KeyParameters = new KeyParameters(new Dictionary<string, (string parameterValue, bool isPrivate)>
            {
                {"k", (key, true)}
            });
        }

        private void NONEParameters()
        {
            KeyParameters = null;
        }

        #endregion Create digital keys

        #region Crypto helper methods

        public bool IsSymmetric()
        {
            return Algorithm.IsSymetric;
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
            if (!IsSymmetric())
                return Export(false);

            return "ToString() is not available for symetric keys. Do not expose private key information.";
        }

        #endregion Helper methods

    }

}
