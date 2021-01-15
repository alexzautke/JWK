using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using CreativeCode.JWK.KeyParts;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK.TypeConverters
{
    public class KeyOperationConverter : IJWKKeyPart
    {
        public object Deserialize(JToken jwkRepresentation)
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
