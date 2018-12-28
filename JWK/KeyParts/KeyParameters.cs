using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CreativeCode.JWK.KeyParts
{
    public sealed class KeyParameters : IJWKKeyPart
    {
        private readonly Dictionary<string, string> values;

        public KeyParameters(Dictionary<string, string> keyParameters){
            values = keyParameters;
        }

        public string Serialize()
        {
            return values.Aggregate(new StringBuilder(),(result,
                                                         currentParameter) => AppendKeyParameter(result, currentParameter), 
                                                         sb => TrimTraillingComma(sb));
        }

        private StringBuilder AppendKeyParameter(StringBuilder current, KeyValuePair<string, string> currentParameter)
        {
            if(currentParameter.Value != string.Empty) // Don't seralize empty JSON properties (i.e., private key parameters if "public key only" mode is requested)
                current.AppendFormat("\"{0}\":\"{1}\",", currentParameter.Key, currentParameter.Value);

            return current;
        }

        private string TrimTraillingComma(StringBuilder sb)
        {
            return sb.ToString().Trim(',');
        }
    }
}
