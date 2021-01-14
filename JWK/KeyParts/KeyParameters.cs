using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK.KeyParts
{
    public sealed class KeyParameters : IJWKKeyPart
    {
        public Dictionary<string, (string parameterValue, bool isPrivate)> Values { get; } // Dictionary<key, Tuple<value, isPrivate>>

        private KeyParameters() { } // Used only for deserialization

        public KeyParameters(Dictionary<string, (string parameterValue, bool isPrivate)> keyParameters){
            if (keyParameters == null)
                throw new ArgumentNullException("Key Parameters cannot be null");

            Values = keyParameters;
        }

        public string Serialize(bool shouldExportPrivateKey = false)
        {
            return Values.Aggregate(new StringBuilder(), (result,
                                                         currentParameter) => AppendKeyParameter(result, currentParameter, shouldExportPrivateKey), 
                                                         TrimTraillingComma);
        }

        private StringBuilder AppendKeyParameter(StringBuilder current, KeyValuePair<string, (string parameterValue, bool isPrivate)> currentParameter, bool shouldExportPrivateKey)
        {
            // Don't seralize empty JSON properties (i.e., private key parameters if "public key only" mode is requested)
            // Don't seralize if value is marked as private and shouldExportPrivateKey is set to false
            if (currentParameter.Value.parameterValue != string.Empty && (!(currentParameter.Value.isPrivate && !shouldExportPrivateKey)))
                current.AppendFormat("\"{0}\":\"{1}\",", currentParameter.Key, currentParameter.Value.parameterValue);

            return current;
        }

        private string TrimTraillingComma(StringBuilder sb)
        {
            return sb.ToString().Trim(',');
        }

        public object Deserialize(JToken jwkRepresentation)
        {
            throw new NotImplementedException();
        }
    }
}
