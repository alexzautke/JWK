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
        public static readonly KeyOperations ComputeDigitalSignature = new KeyOperations("sign");
        public static readonly KeyOperations VerifyDigitalSignature = new KeyOperations("verify");
        public static readonly KeyOperations EncryptContent = new KeyOperations("encrypt");
        public static readonly KeyOperations DecryptContentAndValidateDecryption = new KeyOperations("decrypt");
        public static readonly KeyOperations EncryptKey = new KeyOperations("wrapKey");
        public static readonly KeyOperations DecryptKeyAndValidateDecryption = new KeyOperations("unwrapKey");
        public static readonly KeyOperations DeriveKey = new KeyOperations("deriveKey");
        public static readonly KeyOperations DeriveBits = new KeyOperations("deriveBits");

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
            throw new NotImplementedException();
        }
    }
}
