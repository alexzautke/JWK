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

        public override object? ReadJson(JsonReader reader, Type objectType, object? existingValue, JsonSerializer serializer)
        {
            if (!(objectType == typeof(JWKS)))
                throw new ArgumentException("JWKS Converter can only objects deserialize of type 'JWKS'. Found object of type " + objectType.Name + " instead.");
            
            JObject jo = JObject.Load(reader);
            
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
        
        public override void WriteJson(JsonWriter writer, object? value, JsonSerializer serializer)
        {
            if (!(value is JWKS))
                throw new ArgumentException("JWKS Converter can only objects serialize the type 'JWKS'. Found object of type " + value.GetType() + " instead.");
            
            writer.WriteStartObject();
            writer.WritePropertyName("keys");
            writer.WriteStartArray();

            var jwks = (JWKS) value;
            for(var i = 0; i < jwks.Keys.Count(); i++)
            {
                var keyJSON = jwks.Keys.ElementAt(i).Export(jwks._shouldExportPrivateKey);
                writer.WriteRaw(keyJSON);
                if (i + 1 != jwks.Keys.Count())
                    writer.WriteRaw(",");
            }
            
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
    }
}