using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK.TypeConverters
{
    internal class JWKSConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(JWKS);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (!(objectType == typeof(JWKS)))
                throw new ArgumentException("JWKS Converter can only objects deserialize of type 'JWKS'. Found object of type " + objectType.Name + " instead.");
            
            JObject jo = JsonReading.LoadObject(reader);
            
            var success = jo.TryGetValue("keys", out var token);
            if (!success)
                throw new JsonReaderException("Missing required property 'keys'. Cannot deserialize JWKS.");

            var keys = new List<JWK>();
            foreach (var key in token)
            {
                keys.Add(new JWK(key.ToString()));
            }
            
            return new JWKS(keys);
        }
        
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            // JWKS.Export passes the members to write along with the key set. A JWKS which is serialized directly,
            // without JWKS.Export, is written with the public members of its keys only.
            JWKS jwks;
            KeyMembers members;
            if (value is JWKSExport export)
            {
                jwks = export.KeySet;
                members = export.Members;
            }
            else if (value is JWKS keySet)
            {
                jwks = keySet;
                members = KeyMembers.Public;
            }
            else
                throw new ArgumentException("JWKS Converter can only objects serialize the type 'JWKS'. Found object of type " + value.GetType() + " instead.");
            
            writer.WriteStartObject();
            writer.WritePropertyName("keys");
            writer.WriteStartArray();

            var isFirstKey = true;
            foreach (var key in jwks.Keys)
            {
                if (!isFirstKey)
                    writer.WriteRaw(",");
                isFirstKey = false;

                writer.WriteRaw(key.Export(members));
            }
            
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
    }

    /// <summary>
    /// A JWKS together with the members an export of its keys writes. <see cref="JWKS.Export(KeyMembers)"/> serializes
    /// this instead of the JWKS itself, so that which members are written is part of the call rather than state stored
    /// on the JWKS, which a concurrent export with other members could change halfway through.
    /// </summary>
    [JsonConverter(typeof(JWKSConverter))]
    internal sealed class JWKSExport
    {
        internal JWKS KeySet { get; }
        internal KeyMembers Members { get; }

        internal JWKSExport(JWKS keySet, KeyMembers members)
        {
            KeySet = keySet;
            Members = members;
        }
    }
}