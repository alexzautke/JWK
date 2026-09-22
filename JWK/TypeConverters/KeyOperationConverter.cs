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
            if (jwkRepresentation is null)
                return null;

            var keyOperations = new HashSet<KeyOperation>();
            foreach (var operation in jwkRepresentation.Children())
            {
                var match = TryGetKeyOperation(operation?.ToString());
                if (match is { }) // An empty entry carries no operation and would break serialization
                    keyOperations.Add(match);
            }

            return keyOperations;
        }

        public object Deserialize(JObject jwkRepresentation)
        {
            throw new NotImplementedException();
        }

        public string Serialize(KeyMembers members = KeyMembers.Public, object propertyValue = null)
        {
            var operations = new HashSet<KeyOperation>(propertyValue as IEnumerable<KeyOperation>);
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
