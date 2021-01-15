using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CreativeCode.JWK.KeyParts;
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

            var kty = token.ToString();
            if (kty.Equals(KeyType.RSA.Type))
            {
                foreach(var parameter in KeyParameter.RSAKeyParameters)
                {
                    jwkRepresentation.TryGetValue(parameter.Name, out token);
                    if (token is { })
                        keyParameters.Add(parameter, token.ToString());
                }
            }
            if (kty.Equals(KeyType.EllipticCurve.Type))
            {
                foreach (var parameter in KeyParameter.ECKeyParameters)
                {
                    jwkRepresentation.TryGetValue(parameter.Name, out token);
                    if (token is { })
                        keyParameters.Add(parameter, token.ToString());
                }
            }
            if (kty.Equals(KeyType.OCT.Type))
            {
                foreach (var parameter in KeyParameter.OctKeyParameters)
                {
                    jwkRepresentation.TryGetValue(parameter.Name, out token);
                    if (token is { })
                        keyParameters.Add(parameter, token.ToString());
                }
            }

            return keyParameters;
        }

        public string Serialize(bool shouldExportPrivateKey = false, object propertyValue = null)
        {
            var keyParameters = propertyValue as Dictionary<KeyParameter, string>;
            return keyParameters.Aggregate(new StringBuilder(), (result,
                                             currentParameter) => AppendKeyParameter(result, currentParameter, shouldExportPrivateKey),
                                             TrimTraillingComma);
        }

        private StringBuilder AppendKeyParameter(StringBuilder current, KeyValuePair<KeyParameter, string> currentParameter, bool shouldExportPrivateKey)
        {
            // Don't seralize empty JSON properties (i.e., private key parameters if "public key only" mode is requested)
            // Don't seralize if value is marked as private and shouldExportPrivateKey is set to false
            if (currentParameter.Value != string.Empty && (!(currentParameter.Key.IsPrivate && !shouldExportPrivateKey)))
                current.AppendFormat("\"{0}\":\"{1}\",", currentParameter.Key.Name, currentParameter.Value);

            return current;
        }

        private string TrimTraillingComma(StringBuilder sb)
        {
            return sb.ToString().Trim(',');
        }
    }
}