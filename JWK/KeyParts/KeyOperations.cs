using System;
using System.Collections.Generic;
using CreativeCode.JWK.TypeConverters;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK.KeyParts
{
    // See RFC 7517 - JSON Web Key (JWK) - Section 4.3. "key_ops" (Key Operations) Parameter
    [JsonConverter(typeof(KeyOperationsConverter))]
    public sealed class KeyOperations : IJWKKeyPart
    {
        private const string SIGN_VALUE = "sign";
        private const string VERIFY_VALUE = "verify";
        private const string ENCRYPT_VALUE = "encrypt";
        private const string DECRYPT_VALUE = "decrypt";
        private const string WRAP_KEY_VALUE = "wrapKey";
        private const string UNWRAP_KEY_VALUE = "unwrapKey";
        private const string DERIVE_KEY_VALUE = "deriveKey";
        private const string DERIVE_BITS_VALUE = "deriveBits";

        public static readonly KeyOperations ComputeDigitalSignature = new KeyOperations(SIGN_VALUE);
        public static readonly KeyOperations VerifyDigitalSignature = new KeyOperations(VERIFY_VALUE);
        public static readonly KeyOperations EncryptContent = new KeyOperations(ENCRYPT_VALUE);
        public static readonly KeyOperations DecryptContentAndValidateDecryption = new KeyOperations(DECRYPT_VALUE);
        public static readonly KeyOperations EncryptKey = new KeyOperations(WRAP_KEY_VALUE);
        public static readonly KeyOperations DecryptKeyAndValidateDecryption = new KeyOperations(UNWRAP_KEY_VALUE);
        public static readonly KeyOperations DeriveKey = new KeyOperations(DERIVE_KEY_VALUE);
        public static readonly KeyOperations DeriveBits = new KeyOperations(DERIVE_BITS_VALUE);

        public IEnumerable<string> Operations;

        private KeyOperations() { } // Used only for deserialization

        private KeyOperations(string operation)
        {
            this.Operations = new[] { operation };
        }

        public KeyOperations(IEnumerable<KeyOperations> keyOperations)
        {
            var addedOperations = new List<string>();
            foreach (var keyOperation in keyOperations)
            {
                addedOperations.AddRange(keyOperation.Operations);
            }

            Operations = addedOperations;
        }

        public string Serialize(bool shouldExportPrivateKey = false)
        {
            return JsonConvert.SerializeObject(this);
        }

        public object Deserialize(JToken jwkRepresentation)
        {
            if (jwkRepresentation is null)
                throw new NotSupportedException("Cannot deserialize null value");

            var keyOperations = new List<KeyOperations>();
            foreach(var operation in jwkRepresentation.Children())
            {
                var match = operation.ToString() switch
                {
                    SIGN_VALUE => ComputeDigitalSignature,
                    VERIFY_VALUE => VerifyDigitalSignature,
                    ENCRYPT_VALUE => EncryptContent,
                    DECRYPT_VALUE => DecryptContentAndValidateDecryption,
                    WRAP_KEY_VALUE => EncryptKey,
                    UNWRAP_KEY_VALUE => DeriveKey,
                    DERIVE_KEY_VALUE => DecryptKeyAndValidateDecryption,
                    DERIVE_BITS_VALUE => DeriveBits,
                    _  => null
                };
                keyOperations.Add(match);
            }

            return new KeyOperations(keyOperations);
        }
    }
}
