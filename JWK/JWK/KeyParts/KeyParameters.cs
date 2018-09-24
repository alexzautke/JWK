using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using JWK.TypeConverters;
using Newtonsoft.Json;

namespace JWK.KeyParts
{
    public sealed class KeyParameters
    {
        private readonly Dictionary<string, string> values;

        public KeyParameters(Dictionary<string, string> keyParameters){
            values = keyParameters;
        }

        public override string ToString()
        {
            return values.Aggregate(new StringBuilder(),(result, 
                                                         currentValue) => result.AppendFormat("\"{0}\":\"{1}\",", currentValue.Key, currentValue.Value), 
                                                         sb => sb.ToString().Trim(','));
        }
    }
}
