﻿using System;
using System.Linq;
using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK.TypeConverters
{
	internal class JWKConverter : JsonConverter
    {
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
                    jo.TryGetValue(propertyName, out var token);

                    var customConverterAttribute = property.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(JWKConverterAttribute));
                    if (customConverterAttribute is { }) // Let the type handle the serialization itself as there is a custom serialization needed
                    {
                        var customConverterType = customConverterAttribute.ConstructorArguments.FirstOrDefault(a => a.ArgumentType == typeof(Type)).Value;
                        if (customConverterType is { } && propertyName is { })
                        {
                            var instance = Activator.CreateInstance(customConverterType as Type, true) as IJWKConverter;
                            var instanceValue = instance.Deserialize(token);
                            property.SetValue(jwk, instanceValue);
                        }
                        if (customConverterType is { } && propertyName is null)
                        {
                            var instance = Activator.CreateInstance(customConverterType as Type, true) as IJWKConverter;
                            var instanceValue = instance.Deserialize(jo);
                            property.SetValue(jwk, instanceValue);
                        }
                    }
                    else if (property.PropertyType.GetInterfaces().Any(i => i == typeof(IJWKConverter)))
                    {
                        var instance = Activator.CreateInstance(property.PropertyType, true) as IJWKConverter;
                        var instanceValue = instance.Deserialize(token);
                        property.SetValue(jwk, instanceValue);
                    }
                    else
                    {
                        property.SetValue(jwk, token?.ToString());
                    }
                }
            }

            return jwk;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            if (!(value is JWK))
                throw new ArgumentException("JWK Converter can only objects serialize the type 'JWK'. Found object of type " + value.GetType() + " instead.");
            
            writer.WriteStartObject();

            var type = value.GetType();
            var properties = type.GetProperties(); // Get all public properties
            var head = properties.First();
            var shouldExportPrivateKey = ((JWK)value)._shouldExportPrivateKey;

            foreach (var property in properties)
            {
                var propertyValue = property.GetValue(value);
                if (propertyValue is null)
                    continue;

                foreach (var customAttribute in property.CustomAttributes){
                
                    if (customAttribute.AttributeType != typeof(JsonPropertyAttribute))
                        break; // Only serialize fields which are marked with "JsonProperty"

                    var customJSONPropertyName = customAttribute.NamedArguments.ElementAtOrDefault(0).TypedValue.ToString();
                    WriteTrailingComma(writer, head, property);

                    var customConverterAttribute = property.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(JWKConverterAttribute));
                    if (customConverterAttribute is { }) // Let the type handle the serialization itself as there is a custom serialization needed
                    {
                        var customConverterType = customConverterAttribute.ConstructorArguments.FirstOrDefault(a => a.ArgumentType == typeof(Type)).Value;
                        if(customConverterType is { })
                        {
                            var instance = Activator.CreateInstance(customConverterType as Type, true) as IJWKConverter;
                            writer.WriteRaw(instance.Serialize(shouldExportPrivateKey, propertyValue));
                        }
                    }
                    else if (propertyValue is IJWKConverter)
                        writer.WriteRaw(customJSONPropertyName + ":\"" + ((IJWKConverter)propertyValue).Serialize(shouldExportPrivateKey) + "\"");

                    else // Serialize system types directly
                        writer.WriteRaw(customJSONPropertyName + ":\"" + propertyValue + "\"");
                }
            }

            writer.WriteEndObject();
        }

        private void WriteTrailingComma(JsonWriter writer, PropertyInfo head, PropertyInfo property)
        {
            if (property != head) // Don't start the JSON object with a comma
            {
                writer.WriteRaw(",");
            }
        }

    }
}
