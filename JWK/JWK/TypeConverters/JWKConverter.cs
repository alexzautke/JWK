using System;
using System.Linq;
using System.Reflection;
using Newtonsoft.Json;

namespace JWK.TypeConverters
{
	public class JWKConverter : JsonConverter
    {

        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(JWK);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            // No support for deserialization
            throw new NotImplementedException();
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            writer.WriteStartObject();

            var type = value.GetType();
            FieldInfo[] fields = type.GetFields(BindingFlags.NonPublic|BindingFlags.Instance);
            foreach (var field in fields)
            {
                var propertyValue = field.GetValue(value);
                foreach (var customAttributeData in field.CustomAttributes){
                    if (customAttributeData.AttributeType != typeof(JsonPropertyAttribute))
                    {
                        break; // Only serailize fields which are marked with "JsonProperty"
                    }

                    if (customAttributeData.NamedArguments.Count() > 0) // JWK class indicated a custom name
                    {
                        var customJSONPropertyName = customAttributeData.NamedArguments[0].TypedValue.ToString();
                        writer.WriteRaw(customJSONPropertyName + ":\"" + propertyValue + "\"");
                    }
                    else // Attribute handles JSON property names and formatting itself
                    {
                        writer.WriteRaw(propertyValue.ToString());
                    }

                    if (field != fields.Last())
                    {
                        writer.WriteRaw(",");
                    }
                }
            }

            writer.WriteEndObject();
        }

    }
}
