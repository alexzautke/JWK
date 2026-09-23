using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using CreativeCode.JWK.TypeConverters;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK
{
    [JsonConverter(typeof(JWKSConverter))]
    public class JWKS
    {
        [JsonProperty(PropertyName = "keys")]
        public IEnumerable<JWK> Keys { get; private set; }             // REQUIRED

        internal KeyMembers _exportedMembers;

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
            if (keys is null)
                throw new ArgumentNullException("At least one JWK MUST be provided");
            if (!keys.Any())
                throw new ArgumentException("A JWKS MUST contain at least one JWK, but the given set of keys is empty");

            Keys = keys;
        }

        /// <summary>
        /// Reads a JWKS from its JSON representation, reporting every reason why it is not a valid key set instead of
        /// throwing on the first one. Every key is checked as <see cref="JWK.TryParse"/> checks it, and the key ids
        /// within the set are checked for duplicates. Errors are prefixed with the position of the key they belong to.
        /// </summary>
        /// <param name="jwks">The JSON representation of the JWKS.</param>
        /// <param name="result">The JWKS, or null if it could not be read.</param>
        /// <param name="errors">The reasons why the JWKS was rejected. Empty if this method returned true.</param>
        public static bool TryParse(string jwks, out JWKS result, out IReadOnlyCollection<string> errors)
        {
            result = null;
            var validationErrors = new List<string>();
            errors = validationErrors;

            if (string.IsNullOrWhiteSpace(jwks))
            {
                validationErrors.Add("The JWKS is empty.");
                return false;
            }

            JObject jwksRepresentation;
            try
            {
                jwksRepresentation = JObject.Parse(jwks);
            }
            catch (JsonException e)
            {
                validationErrors.Add($"The JWKS is not a valid JSON object. Reason: {e.Message}");
                return false;
            }

            if (!jwksRepresentation.TryGetValue("keys", out var keysToken))
            {
                validationErrors.Add("The 'keys' member is missing. It is a mandatory element and MUST be present.");
                return false;
            }

            if (!(keysToken is JArray keyTokens))
            {
                validationErrors.Add("The 'keys' member MUST be a JSON array.");
                return false;
            }

            if (keyTokens.Count == 0)
            {
                validationErrors.Add("The 'keys' array is empty. A JWKS MUST contain at least one JWK.");
                return false;
            }

            var keys = new List<JWK>();
            var keyIds = new HashSet<string>();
            for (var i = 0; i < keyTokens.Count; i++)
            {
                if (!JWK.TryParse(keyTokens[i].ToString(), out var key, out var keyErrors))
                {
                    validationErrors.AddRange(keyErrors.Select(error => $"Key at position {i}: {error}"));
                    continue;
                }

                if (key.KeyID is { } && !keyIds.Add(key.KeyID))
                    validationErrors.Add($"Key at position {i}: the key id '{key.KeyID}' is used by more than one key in this set.");

                keys.Add(key);
            }

            if (validationErrors.Count > 0)
                return false;

            result = new JWKS(keys);
            return true;
        }

        /// <summary>
        /// The JSON representation of this JWKS.
        /// </summary>
        /// <param name="members">
        /// Which members of each key to write. Defaults to <see cref="KeyMembers.Public"/>; pass
        /// <see cref="KeyMembers.All"/> to include the private key material.
        /// </param>
        public string Export(KeyMembers members = KeyMembers.Public)
        {
            #if DEBUG
                var performanceStopWatch = new Stopwatch();
                performanceStopWatch.Start();
            #endif

            _exportedMembers = members;

            foreach (var key in Keys)
            {
                if(key.IsSymmetric() && members == KeyMembers.Public)
                    throw new CryptographicException("Symmetric key of type " + (key.KeyType?.Serialize() ?? "(unknown)") + " has no public members and cannot be exported with KeyMembers.Public.");
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
