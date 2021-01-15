using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using CreativeCode.JWK.KeyParts;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using static CreativeCode.JWK.KeyParts.KeyOperation;

namespace CreativeCode.JWK.TypeConverters
{
    internal class KeyOperationConverter : IJWKConverter
    {
        public object Deserialize(JToken jwkRepresentation)
        {
            var keyOperations = new HashSet<KeyOperation>();
            foreach (var operation in jwkRepresentation.Children())
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
                    _ => null
                };
                keyOperations.Add(match);
            }

            return keyOperations;
        }

        public object Deserialize(JObject jwkRepresentation)
        {
            throw new NotImplementedException();
        }

        public string Serialize(bool shouldExportPrivateKey = false, object propertyValue = null)
        {
            var operations = propertyValue as HashSet<KeyOperation>;
            var sb = new StringBuilder();
            var sw = new StringWriter(sb);
            var writer = new JsonTextWriter(sw);
            writer.WritePropertyName("key_ops");
            writer.WriteStartArray();
            foreach (var operation in operations)
            {
                writer.WriteValue(operation.Operation);
            }
            writer.WriteEnd();

            return sb.ToString();
        }
    }
}
