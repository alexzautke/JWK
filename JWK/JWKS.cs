using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using CreativeCode.JWK.TypeConverters;
using Newtonsoft.Json;

namespace CreativeCode.JWK
{
    [JsonConverter(typeof(JWKSConverter))]
    public class JWKS
    {
        [JsonProperty(PropertyName = "keys")]
        public IEnumerable<JWK> Keys { get; private set; }             // REQUIRED
        
        internal bool _shouldExportPrivateKey;
        
        public JWKS(string jwks)
        {
            try
            {
                var deserializeJWKS = JsonConvert.DeserializeObject<JWKS>(jwks);
                Keys = deserializeJWKS.Keys;   
            }
            catch(JsonReaderException e)
            {
                throw new InvalidOperationException($"Could not deserialize JWK. Reason: {e.Message}");
            }
        }

        public JWKS(IEnumerable<JWK> keys)
        {
            if (keys is null || !keys.Any())
                throw new ArgumentNullException("At least one JWK MUST be provided");

            Keys = keys;
        }

        public string Export(bool shouldExportPrivateKey = false)
        {
            #if DEBUG
                var performanceStopWatch = new Stopwatch();
                performanceStopWatch.Start();
            #endif

            _shouldExportPrivateKey = shouldExportPrivateKey;
            
            foreach (var key in Keys)
            {
                if(key.IsSymmetric() && !shouldExportPrivateKey)
                    throw new CryptographicException("Symmetric key of type " + key.KeyType.Serialize() + " cannot be exported with shouldExportPrivateKey set to false.");
            }
            
            var jwksJSON = JsonConvert.SerializeObject(this);
            
            #if DEBUG
                performanceStopWatch.Stop();
                Console.WriteLine($"Debug Information - CreativeCode.JWK - Successfully serialized JWKS. It took {performanceStopWatch.Elapsed.TotalMilliseconds}ms.");
            #endif
            
            return jwksJSON;
        }
    }
}