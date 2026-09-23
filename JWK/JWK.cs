using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using CreativeCode.JWK.KeyParts;
using CreativeCode.JWK.TypeConverters;
using CreativeCode.JWK.Validation;
using System.Linq;
using static CreativeCode.JWK.KeyParts.KeyParameter;
using static CreativeCode.JWK.Base64Helper;

namespace CreativeCode.JWK
{
    [JsonConverter(typeof(JWKConverter))]
    public class JWK
    {
        private const int MinimumRsaKeySize = 2048;  // See recommendations: https://www.keylength.com/en/compare/
        private const int MaximumRsaKeySize = 16384; // See https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider.keysize?source=recommendations&view=net-7.0

        [JsonProperty(PropertyName = "kty")]
        public KeyType KeyType { get; private set; }             // REQUIRED

        [JsonProperty(PropertyName = "use")]
        public PublicKeyUse PublicKeyUse { get; private set; }   // OPTIONAL

        [JsonProperty(PropertyName = "key_ops")]
        [JWKConverterAttribute(typeof(KeyOperationConverter))]
        public IEnumerable<KeyOperation> KeyOperations { get; private set; } // OPTIONAL

        [JsonProperty(PropertyName = "alg")]
        public Algorithm Algorithm { get; private set; }         // OPTIONAL

        [JsonProperty(PropertyName = "kid")]
        public string KeyID { get; private set; }                // OPTIONAL

        [JsonProperty]
        [JWKConverterAttribute(typeof(KeyParameterConverter))]
        public Dictionary<KeyParameter, string> KeyParameters { get; private set; } // OPTIONAL

        /// <summary>
        /// The members of the JWK which this library does not interpret (e.g. "x5c", or every member of a key type it
        /// has no support for), as their raw JSON. They are written again by <see cref="Export"/>, so that reading and
        /// exporting a JWK does not silently drop information.
        /// Because this library cannot tell whether such a member carries private key material, only the members
        /// registered in RFC 7517 - Section 4 are written by a public key export; the rest are withheld unless the
        /// private key is exported as well.
        /// </summary>
        public IReadOnlyDictionary<string, string> AdditionalMembers { get; private set; } = new Dictionary<string, string>();

        internal KeyMembers _exportedMembers;

        private JWK() { } // Used only for deserialization

        internal void SetAdditionalMembers(IReadOnlyDictionary<string, string> additionalMembers)
        {
            AdditionalMembers = additionalMembers ?? new Dictionary<string, string>();
        }

        /// <summary>
        /// Deserialize a JWK from string
        /// Mandatory elements MUST be provided
        /// </summary>
        /// <param name="jwk"></param>
        public JWK(string jwk)
        {
            try
            {
                var deserializeJWK = JsonConvert.DeserializeObject<JWK>(jwk);

                KeyType = deserializeJWK.KeyType;
                PublicKeyUse = deserializeJWK.PublicKeyUse;
                KeyOperations = deserializeJWK.KeyOperations;
                Algorithm = deserializeJWK.Algorithm;
                KeyID = deserializeJWK.KeyID;
                KeyParameters = deserializeJWK.KeyParameters;
                AdditionalMembers = deserializeJWK.AdditionalMembers;
            }
            catch(JsonReaderException e)
            {
                throw new InvalidOperationException($"Could not deserialize JWK. Reason: {e.Message}");
            }
        }

        /// <summary>
        /// Create a JWK using only required elements
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="keyParameters"></param>
        public JWK(KeyType keyType, Dictionary<KeyParameter, string> keyParameters)
        {
            KeyType = keyType ?? throw new ArgumentNullException("KeyType MUST be provided");
            KeyParameters = keyParameters ?? throw new ArgumentNullException("KeyParameters MUST be provided");
        }

        /// <summary>
        /// Create a JWK with optionally all elements
        /// </summary>
        /// <param name="keyType"></param>
        /// <param name="keyParameters"></param>
        /// <param name="publicKeyUse"></param>
        /// <param name="keyOperations"></param>
        /// <param name="algorithm"></param>
        /// <param name="keyId"></param>
        public JWK(KeyType keyType, Dictionary<KeyParameter, string> keyParameters, PublicKeyUse publicKeyUse = null, IEnumerable<KeyOperation> keyOperations = null, Algorithm algorithm = null, string keyId = null): this(keyType, keyParameters)
        {
            PublicKeyUse = publicKeyUse;
            KeyOperations = new HashSet<KeyOperation>(keyOperations);
            Algorithm = algorithm;
            KeyID = keyId;
        }

        /// <summary>
        /// Create a JWK by only providing a specific algorithm. A new key for the corresponding algorithm is generated in the background
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="publicKeyUse"></param>
        /// <param name="keyOperations"></param>
        public JWK(Algorithm algorithm, PublicKeyUse publicKeyUse = null, IEnumerable<KeyOperation> keyOperations = null, int? rsaKeySize = null)
        {
            PublicKeyUse = publicKeyUse;
            KeyOperations = keyOperations;
            Algorithm = algorithm;
            KeyID = Guid.NewGuid().ToString();
            KeyType = DeriveKeyType(algorithm);

            if (KeyType is null)
                throw new ArgumentException($"Cannot create a new key for algorithm '{algorithm?.Name}'. A new key can only be created for the RSA (RS*), elliptic curve (ES*), HMAC (HS*) and AES (A*GCMKW) algorithms.");

            if (KeyType != KeyType.RSA && rsaKeySize is { })
                throw new ArgumentException("rsaKeySize can only be provided if KeyType is RSA");

            InitializeKey(rsaKeySize);
        }

        private KeyType DeriveKeyType(Algorithm algorithm)
        {
            if (algorithm is null || !algorithm.IsRecognized)
                return null;
            if (algorithm.IsSymetric)
                return KeyType.OCT;
            if (algorithm == Algorithm.RS256 || algorithm == Algorithm.RS384 || algorithm == Algorithm.RS512)
                return KeyType.RSA;
            if (algorithm == Algorithm.ES256 || algorithm == Algorithm.ES384 || algorithm == Algorithm.ES512)
                return KeyType.EllipticCurve;

            return null;
        }

        private void InitializeKey(int? rsaKeySize = null)
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
                    rsaKeySize ??= MinimumRsaKeySize;
                    rsaKeySize = Math.Max(rsaKeySize.Value, MinimumRsaKeySize);

                    if(rsaKeySize is null)
                        throw new InvalidOperationException("rsaKeySize must be provided if a key with KeyType RSA is initialized");

                    if (rsaKeySize > MaximumRsaKeySize)
                        throw new CryptographicException($"rsaKeySize is too large. Maximum key size is '{MaximumRsaKeySize}' bits");

                    RSAParameters(rsaKeySize.Value);
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
                Console.WriteLine($"Debug Information - CreativeCode.JWK - Successfully initialized new key for JWK of type '{KeyType.Type}'. It took " + performanceStopWatch.Elapsed.TotalMilliseconds + "ms.");
            #endif
        }

        /// <summary>
        /// The JSON representation of this JWK.
        /// </summary>
        /// <param name="members">
        /// Which members to write. Defaults to <see cref="KeyMembers.Public"/>; pass <see cref="KeyMembers.All"/> to
        /// include the private key material.
        /// </param>
        public string Export(KeyMembers members = KeyMembers.Public)
        {
            _exportedMembers = members;
            if (members == KeyMembers.Public && IsSymmetric())
                throw new CryptographicException("Symmetric key of type " + (KeyType?.Serialize() ?? "(unknown)") + " has no public members and cannot be exported with KeyMembers.Public.");

            return JsonConvert.SerializeObject(this);
        }

        [Obsolete("Use Export(KeyMembers) instead. Export(true) is Export(KeyMembers.All), Export(false) is Export(KeyMembers.Public).")]
        public string Export(bool shouldExportPrivateKey)
        {
            return Export(shouldExportPrivateKey ? KeyMembers.All : KeyMembers.Public);
        }

        #region Validating parse

        /// <summary>
        /// Reads a JWK from its JSON representation, reporting every reason why it is not a valid key instead of
        /// throwing on the first one. What is checked is RFC 7517 / RFC 7518 key validity only: whether the key type
        /// is supported, whether the parameters it requires are present and encoded correctly, and - for an elliptic
        /// curve key - whether the public key is a point on the curve. Which algorithms, key sizes or key ids a
        /// caller is willing to accept is policy and remains the caller's own decision.
        /// </summary>
        /// <param name="jwk">The JSON representation of the JWK.</param>
        /// <param name="result">The JWK, or null if it could not be read.</param>
        /// <param name="errors">The reasons why the JWK was rejected. Empty if this method returned true.</param>
        public static bool TryParse(string jwk, out JWK result, out IReadOnlyCollection<string> errors)
        {
            result = null;
            var validationErrors = new List<string>();
            errors = validationErrors;

            if (string.IsNullOrWhiteSpace(jwk))
            {
                validationErrors.Add("The JWK is empty.");
                return false;
            }

            JObject jwkRepresentation;
            try
            {
                jwkRepresentation = JObject.Parse(jwk);
            }
            catch (JsonException e)
            {
                validationErrors.Add($"The JWK is not a valid JSON object. Reason: {e.Message}");
                return false;
            }

            validationErrors.AddRange(JWKValidator.ValidateRepresentation(jwkRepresentation));
            if (validationErrors.Count > 0)
                return false; // A JWK whose JSON does not have the expected shape cannot be read reliably

            JWK parsedJWK;
            try
            {
                parsedJWK = new JWK(jwk);
            }
            catch (Exception e)
            {
                validationErrors.Add($"The JWK could not be read. Reason: {e.Message}");
                return false;
            }

            validationErrors.AddRange(JWKValidator.ValidateKey(parsedJWK));
            if (validationErrors.Count > 0)
                return false;

            result = parsedJWK;
            return true;
        }

        /// <summary>
        /// Checks the key material of this JWK, reporting every reason why it is not a valid key. See
        /// <see cref="TryParse"/> for what is and is not checked.
        /// </summary>
        public bool TryValidate(out IReadOnlyCollection<string> errors)
        {
            var validationErrors = JWKValidator.ValidateKey(this);
            errors = validationErrors;

            return validationErrors.Count == 0;
        }

        #endregion Validating parse

        #region Convert to .NET key parameters

        /// <summary>
        /// The RSA key parameters of this JWK. The private key parameters are included if this JWK carries them.
        /// </summary>
        /// <exception cref="InvalidOperationException">This JWK does not contain a usable RSA key.</exception>
        public RSAParameters ToRSAParameters()
        {
            if (KeyType != KeyType.RSA)
                throw new InvalidOperationException($"A key of type '{KeyType}' cannot be converted to RSA key parameters.");
            if (KeyParameters is { } && KeyParameters.ContainsKey(RSAKeyParameterOTH))
                throw new InvalidOperationException("Multi-prime RSA keys (key parameter 'oth') are not supported.");

            var modulus = RequiredParameter(RSAKeyParameterN);
            var parameters = new RSAParameters
            {
                Modulus = modulus,
                Exponent = RequiredParameter(RSAKeyParameterE)
            };

            var privateParameters = new[] { RSAKeyParameterD, RSAKeyParameterP, RSAKeyParameterQ, RSAKeyParameterDP, RSAKeyParameterDQ, RSAKeyParameterQI };
            var providedPrivateParameters = privateParameters.Where(HasParameter).ToList();
            if (providedPrivateParameters.Count == 0)
                return parameters;

            if (providedPrivateParameters.Count != privateParameters.Length)
                throw new InvalidOperationException($"A private RSA key can only be converted if all of 'd', 'p', 'q', 'dp', 'dq' and 'qi' are present. The key parameters '{string.Join("', '", privateParameters.Where(p => !HasParameter(p)).Select(p => p.Name))}' are missing.");

            // A Base64urlUInt is stored without leading zero octets, but RSAParameters expects each value padded to
            // the length of the modulus (or half of it for the CRT parameters).
            var halfModulusLength = (modulus.Length + 1) / 2;
            parameters.D = LeftPad(RequiredParameter(RSAKeyParameterD), modulus.Length);
            parameters.P = LeftPad(RequiredParameter(RSAKeyParameterP), halfModulusLength);
            parameters.Q = LeftPad(RequiredParameter(RSAKeyParameterQ), halfModulusLength);
            parameters.DP = LeftPad(RequiredParameter(RSAKeyParameterDP), halfModulusLength);
            parameters.DQ = LeftPad(RequiredParameter(RSAKeyParameterDQ), halfModulusLength);
            parameters.InverseQ = LeftPad(RequiredParameter(RSAKeyParameterQI), halfModulusLength);

            return parameters;
        }

        /// <summary>
        /// The elliptic curve key parameters of this JWK. The private key parameter is included if this JWK carries it.
        /// </summary>
        /// <exception cref="InvalidOperationException">This JWK does not contain a usable elliptic curve key.</exception>
        public ECParameters ToECParameters()
        {
            if (KeyType != KeyType.EllipticCurve)
                throw new InvalidOperationException($"A key of type '{KeyType}' cannot be converted to elliptic curve key parameters.");

            var curve = GetCurve();
            if (curve is null)
                throw new InvalidOperationException($"The curve '{StringParameter(ECKeyParameterCRV)}' is not supported.");

            var parameters = new ECParameters
            {
                Curve = curve.ToECCurve(),
                Q = new ECPoint
                {
                    X = LeftPad(RequiredParameter(ECKeyParameterX), curve.CoordinateLength),
                    Y = LeftPad(RequiredParameter(ECKeyParameterY), curve.CoordinateLength)
                }
            };

            if (HasParameter(ECKeyParameterD))
                parameters.D = LeftPad(RequiredParameter(ECKeyParameterD), curve.CoordinateLength);

            return parameters;
        }

        /// <summary>
        /// The size of this key in bits: the size of the modulus of an RSA key, the size of the curve of an elliptic
        /// curve key, or the length of the key material of a symmetric key.
        /// </summary>
        /// <exception cref="InvalidOperationException">The size of this key cannot be determined.</exception>
        public int GetKeySizeInBits()
        {
            if (KeyType == KeyType.RSA)
                return JWKValidator.BitLength(RequiredParameter(RSAKeyParameterN));

            if (KeyType == KeyType.EllipticCurve)
            {
                var curve = GetCurve();
                if (curve is null)
                    throw new InvalidOperationException($"The curve '{StringParameter(ECKeyParameterCRV)}' is not supported.");

                return curve.KeySizeInBits;
            }

            if (KeyType == KeyType.OCT)
                return RequiredParameter(OctKeyParameterK).Length * 8;

            throw new InvalidOperationException($"The size of a key of type '{KeyType}' cannot be determined.");
        }

        /// <summary>
        /// The curve of this elliptic curve key, or null if this JWK has no curve or one which is not supported.
        /// </summary>
        public EllipticCurve GetCurve()
        {
            return EllipticCurve.TryGetCurve(StringParameter(ECKeyParameterCRV));
        }

        private bool HasParameter(KeyParameter keyParameter)
        {
            return !string.IsNullOrEmpty(StringParameter(keyParameter));
        }

        private string StringParameter(KeyParameter keyParameter)
        {
            if (KeyParameters is null || !KeyParameters.TryGetValue(keyParameter, out var value))
                return null;

            return value;
        }

        private byte[] RequiredParameter(KeyParameter keyParameter)
        {
            var value = StringParameter(keyParameter);
            if (string.IsNullOrEmpty(value))
                throw new InvalidOperationException($"The key parameter '{keyParameter.Name}' is missing.");
            if (!TryBase64urlDecode(value, out var decoded))
                throw new InvalidOperationException($"The key parameter '{keyParameter.Name}' is not a valid base64url encoded value.");

            return decoded;
        }

        private static byte[] LeftPad(byte[] value, int length)
        {
            if (value.Length >= length)
                return value;

            var padded = new byte[length];
            Array.Copy(value, 0, padded, length - value.Length, value.Length);

            return padded;
        }

        #endregion Convert to .NET key parameters

        #region Create digital keys

        private void ECParameters()
        {
            var curve = EllipticCurve.TryGetCurveForAlgorithm(Algorithm);
            if (curve is null)
                throw new ArgumentException("Could not create ECCurve based on algorithm: " + Algorithm.Serialize());

            ECDsa eCDsa = ECDsa.Create();
            eCDsa.GenerateKey(curve.ToECCurve());

            ECParameters eCParameters = eCDsa.ExportParameters(true);
            var privateKeyD = Base64urlEncode(eCParameters.D);
            var publicKeyX = Base64urlEncode(eCParameters.Q.X);
            var publicKeyY = Base64urlEncode(eCParameters.Q.Y);

            KeyParameters = new Dictionary<KeyParameter, string>
            {
                {ECKeyParameterCRV, curve.Name},
                {ECKeyParameterX, publicKeyX},
                {ECKeyParameterY, publicKeyY},
                {ECKeyParameterD, privateKeyD}
            };
        }

        private void RSAParameters(int rsaKeySize)
        {
            using (var rsaKey = new RSACryptoServiceProvider(rsaKeySize)){

                var rsaKeyParameters = rsaKey.ExportParameters(true);

                // RSAParameters properties are big-endian, no need to reverse the byte array (See RFC7518 - 6.3.1. Parameters for RSA Public Keys)
                // They are also padded to a fixed length, while a Base64urlUInt carries no leading zero octets.
                var modulus = Base64urlEncodeUInt(rsaKeyParameters.Modulus);
                var exponent = Base64urlEncodeUInt(rsaKeyParameters.Exponent);
                var privateExponent = Base64urlEncodeUInt(rsaKeyParameters.D);
                var firstPrimeFactor = Base64urlEncodeUInt(rsaKeyParameters.P);
                var secondPrimeFactor = Base64urlEncodeUInt(rsaKeyParameters.Q);
                var firstFactorCRTExponent = Base64urlEncodeUInt(rsaKeyParameters.DP);
                var secondFactorCRTExponent = Base64urlEncodeUInt(rsaKeyParameters.DQ);
                var firstCRTCoefficient = Base64urlEncodeUInt(rsaKeyParameters.InverseQ);

                KeyParameters = new Dictionary<KeyParameter, string>
                {
                    {RSAKeyParameterN, modulus},
                    {RSAKeyParameterE, exponent},
                    {RSAKeyParameterD, privateExponent},
                    {RSAKeyParameterP, firstPrimeFactor},
                    {RSAKeyParameterQ, secondPrimeFactor},
                    {RSAKeyParameterDP, firstFactorCRTExponent},
                    {RSAKeyParameterDQ, secondFactorCRTExponent},
                    {RSAKeyParameterQI, firstCRTCoefficient}
                };
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
            KeyParameters = new Dictionary<KeyParameter, string>
            {
                {OctKeyParameterK, key}
            };
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
            KeyParameters = new Dictionary<KeyParameter, string>
            {
                {OctKeyParameterK, key}
            };
        }

        private void NONEParameters()
        {
            KeyParameters = null;
        }

        #endregion Create digital keys

        #region Crypto helper methods

        public bool IsSymmetric()
        {
            // An algorithm which is not recognized says nothing about the key, so fall back to the key type
            if (Algorithm is { } && Algorithm.IsRecognized)
                return Algorithm.IsSymetric;

            return KeyType == KeyType.OCT;
        }

        #endregion Crypto helper methods

        #region Helper methods

        public override string ToString()
        {
            if (!IsSymmetric())
                return Export(KeyMembers.Public);

            return "ToString() is not available for symmetric keys. Do not expose private key information.";
        }

        #endregion Helper methods

    }

}
