using System;
using JWK.KeyParts;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JWK.TypeConverters
{
	public class KeyParametersConverter : JsonConverter
    {

        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(KeyParameters);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            // No support for deserialization
            throw new NotImplementedException();
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
          
        }
    }
}
