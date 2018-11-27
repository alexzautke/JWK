using System;
using System.Linq;
using System.Reflection;
using Newtonsoft.Json;

namespace JWK.TypeConverters
{
	public class JWKConverter : JsonConverter
    {

        private JsonWriter _writer;

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
            _writer = writer;
            _writer.WriteStartObject();

            var type = value.GetType();
            FieldInfo[] fields = type.GetFields(BindingFlags.NonPublic|BindingFlags.Instance);
            foreach (var field in fields)
            {
                var propertyValue = field.GetValue(value);
                foreach (var customAttributeData in field.CustomAttributes){

                    if (customAttributeData.AttributeType != typeof(JsonPropertyAttribute))
                    {
                        break; // Only serialize fields which are marked with "JsonProperty"
                    }

                    if (customAttributeData.NamedArguments.Count() > 0) // JWK class indicated a custom name
                    {
                        var customJSONPropertyName = customAttributeData.NamedArguments[0].TypedValue.ToString();
                        WriteTrailingComma(fields, field);
                        _writer.WriteRaw(customJSONPropertyName + ":\"" + propertyValue + "\"");
                    }
                    else // Attribute handles JSON property name and formatting itself
                    {
                        if(propertyValue != null)
                        {
                            WriteTrailingComma(fields, field);
                            _writer.WriteRaw(propertyValue.ToString());
                        }
                    }
                }
            }

            _writer.WriteEndObject();
        }

        private void WriteTrailingComma(FieldInfo[] fields, FieldInfo field){
            if (field != fields.First()) // Don't start the JSON object with a comma
            {
                _writer.WriteRaw(",");
            }
        }

    }
}
