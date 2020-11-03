using System;
using CreativeCode.JWK.KeyParts;
using Newtonsoft.Json;

namespace CreativeCode.JWK.TypeConverters
{
    public class KeyOperationsConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(KeyOperations);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            // No support for deserialization
            throw new NotImplementedException();
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            if (!(value is KeyOperations))
                throw new ArgumentException("KeyOperationsConverter can only convert objects of type KeyOperations. Found object of type " + value.GetType() + " instead.");

            var keyOperations = value as KeyOperations;
            writer.WritePropertyName("key_ops");
            writer.WriteStartArray();
            foreach(var operation in keyOperations.Operations)
            {
                writer.WriteValue(operation);
            }
            writer.WriteEnd();
        }
    }
}
