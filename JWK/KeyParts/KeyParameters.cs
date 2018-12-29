using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CreativeCode.JWK.KeyParts
{
    public sealed class KeyParameters : IJWKKeyPart
    {
        private readonly Dictionary<string, (string parameterValue, bool isPrivate)> values; // Dictionary<key, Tuple<value, isPrivate>>

        public KeyParameters(Dictionary<string, (string parameterValue, bool isPrivate)> keyParameters){
            values = keyParameters;
        }

        public string Serialize(bool shouldExportPrivateKey = false)
        {
            return values.Aggregate(new StringBuilder(), (result,
                                                         currentParameter) => AppendKeyParameter(result, currentParameter, shouldExportPrivateKey), 
                                                         TrimTraillingComma);
        }

        private StringBuilder AppendKeyParameter(StringBuilder current, KeyValuePair<string, (string parameterValue, bool isPrivate)> currentParameter, bool shouldExportPrivateKey)
        {
            // Don't seralize empty JSON properties (i.e., private key parameters if "public key only" mode is requested)
            // Don't seralize if value is marked as private and shouldExportPrivateKey is set to false
            if (currentParameter.Value.Item1 != string.Empty && (!(currentParameter.Value.isPrivate && !shouldExportPrivateKey)))
                current.AppendFormat("\"{0}\":\"{1}\",", currentParameter.Key, currentParameter.Value.parameterValue);

            return current;
        }

        private string TrimTraillingComma(StringBuilder sb)
        {
            return sb.ToString().Trim(',');
        }
    }
}
