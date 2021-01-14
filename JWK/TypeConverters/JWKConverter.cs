using System;
using System.Linq;
using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK.TypeConverters
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
            if (!(objectType == typeof(JWK)))
                throw new ArgumentException("JWK Converter can only objects deserialize of type 'JWK'. Found object of type " + objectType.Name + " instead.");

            JObject jo = JObject.Load(reader);
            var jwk = Activator.CreateInstance(objectType, true) as JWK;

            var properties = objectType.GetProperties(); // Get all public properties
            foreach (var property in properties)
            {
                foreach (var customAttributeData in property.CustomAttributes)
                {
                    if (customAttributeData.AttributeType != typeof(JsonPropertyAttribute))
                        break; // Only deserialize fields which are marked with "JsonProperty"

                    // Get token by name indicated by JsonPropertyAttribute
                    var propertyNameArgument = customAttributeData.NamedArguments.FirstOrDefault(n => n.MemberName == "PropertyName");
                    var propertyName = propertyNameArgument.TypedValue.Value as string;
                    if (propertyName is null)
                        break;

                    jo.TryGetValue(propertyName, out var token);

                    if (property.PropertyType.GetInterfaces().Any(i => i == typeof(IJWKKeyPart))) // Custom Deserialization needed
                    {
                        var instance = Activator.CreateInstance(property.PropertyType, true) as IJWKKeyPart;
                        var instanceValue = instance.Deserialize(token);
                        property.SetValue(jwk, instanceValue);
                    }
                    else
                    {
                        property.SetValue(jwk, token.ToString());
                    }
                }
            }

            return jwk;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            if (!(value is JWK))
                throw new ArgumentException("JWK Converter can only objects serialize the type 'JWK'. Found object of type " + value.GetType() + " instead.");

            _writer = writer;
            _writer.WriteStartObject();

            var type = value.GetType();
            var properties = type.GetProperties(); // Get all public properties
            var head = properties.First();
            var shouldExportPrivateKey = ((JWK)value)._shouldExportPrivateKey;

            foreach (var property in properties)
            {
                var propertyValue = property.GetValue(value);
                foreach (var customAttributeData in property.CustomAttributes){
                
                    if (customAttributeData.AttributeType != typeof(JsonPropertyAttribute))
                        break; // Only serialize fields which are marked with "JsonProperty"

                    if (customAttributeData.NamedArguments.Any()) // JWK class indicated a custom name
                    {
                        var customJSONPropertyName = customAttributeData.NamedArguments[0].TypedValue.ToString();
                        WriteTrailingComma(head, property);

                        if(propertyValue is IJWKKeyPart)
                            _writer.WriteRaw(customJSONPropertyName + ":\"" + ((IJWKKeyPart)propertyValue).Serialize(shouldExportPrivateKey) + "\""); // Complex object which is part of CretaiveCode.JWK.KeyParts
                        else
                            _writer.WriteRaw(customJSONPropertyName + ":\"" + propertyValue + "\""); // System-provided object like GUID
                    }
                    else // Attribute handles JSON property name and formatting itself
                    { 
                        WriteTrailingComma(head, property);
                        _writer.WriteRaw(((IJWKKeyPart)propertyValue).Serialize(shouldExportPrivateKey)); // Needed for KeyParameter and KeyOperations objects
                    }
                }
            }

            _writer.WriteEndObject();
        }

        private void WriteTrailingComma(PropertyInfo head, PropertyInfo property)
        {
            if (property != head) // Don't start the JSON object with a comma
            {
                _writer.WriteRaw(",");
            }
        }

    }
}
