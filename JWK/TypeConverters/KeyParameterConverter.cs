using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CreativeCode.JWK.KeyParts;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK.TypeConverters
{
    internal class KeyParameterConverter : IJWKConverter
    {
        public object Deserialize(JToken jwkRepresentation)
        {
            throw new System.NotImplementedException();
        }

        public object Deserialize(JObject jwkRepresentation)
        {
            var keyParameters = new Dictionary<KeyParameter, string>();
            jwkRepresentation.TryGetValue("kty", out var token);
            if (token is null)
                throw new InvalidOperationException("Cannot deserialize Key Parameters if Key Type is not present");

            var keyType = KeyType.TryGetKeyType(token.ToString());
            foreach (var parameter in KeyParameter.ParametersFor(keyType))
            {
                jwkRepresentation.TryGetValue(parameter.Name, out token);
                if (token is { })
                    keyParameters.Add(parameter, ValueOf(parameter, token));
            }

            return keyParameters;
        }

        // A parameter which is not a JSON string (currently only "oth") is kept as its raw JSON text, so that it can
        // be written back unchanged.
        private static string ValueOf(KeyParameter parameter, JToken token)
        {
            return parameter.Encoding == KeyParameterEncoding.Json
                ? token.ToString(Formatting.None)
                : token.ToString();
        }

        public string Serialize(KeyMembers members = KeyMembers.Public, object propertyValue = null)
        {
            var keyParameters = propertyValue as Dictionary<KeyParameter, string>;
            return keyParameters.Aggregate(new StringBuilder(), (result,
                                             currentParameter) => AppendKeyParameter(result, currentParameter, members),
                                             TrimTraillingComma);
        }

        private StringBuilder AppendKeyParameter(StringBuilder current, KeyValuePair<KeyParameter, string> currentParameter, KeyMembers members)
        {
            // Don't seralize empty JSON properties (i.e., private key parameters if "public key only" mode is requested)
            // Don't seralize if the value is marked as private and only the public members are exported
            if (currentParameter.Value != string.Empty && (!(currentParameter.Key.IsPrivate && members == KeyMembers.Public)))
            {
                if (currentParameter.Key.Encoding == KeyParameterEncoding.Json)
                    current.AppendFormat("\"{0}\":{1},", currentParameter.Key.Name, currentParameter.Value);
                else
                    current.AppendFormat("\"{0}\":{1},", currentParameter.Key.Name, JsonConvert.ToString(currentParameter.Value));
            }

            return current;
        }

        private string TrimTraillingComma(StringBuilder sb)
        {
            return sb.ToString().Trim(',');
        }
    }
}
