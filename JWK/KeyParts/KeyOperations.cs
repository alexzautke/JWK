using System;
using System.Collections.Generic;
using CreativeCode.JWK.TypeConverters;
using Newtonsoft.Json;

namespace CreativeCode.JWK.KeyParts
{
    // See RFC 7517 - JSON Web Key (JWK) - Section 4.3. "key_ops" (Key Operations) Parameter
    [JsonConverter(typeof(KeyOperationsConverter))]
    public sealed class KeyOperations : IJWKKeyPart
    {
        public static readonly KeyOperations ComputeDigitalSignature = new KeyOperations(new[] { "sign" });
        public static readonly KeyOperations VerifyDigitalSignature = new KeyOperations(new[] { "verify" });
        public static readonly KeyOperations EncryptContent = new KeyOperations(new[] { "encrypt" });
        public static readonly KeyOperations DecryptContentAndValidateDecryption = new KeyOperations(new[] { "decrypt" });
        public static readonly KeyOperations EncryptKey = new KeyOperations(new[] { "wrapKey" });
        public static readonly KeyOperations DecryptKeyAndValidateDecryption = new KeyOperations(new[] { "unwrapKey" });
        public static readonly KeyOperations DeriveKey = new KeyOperations(new[] { "deriveKey" });
        public static readonly KeyOperations DeriveBits = new KeyOperations(new[] { "deriveBits" });

        public IEnumerable<string> Operations;

        private KeyOperations(IEnumerable<string> operations)
        {
            this.Operations = operations;
        }

        public string Serialize(bool shouldExportPrivateKey = false)
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}
