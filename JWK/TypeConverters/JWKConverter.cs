using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK.TypeConverters
{
	internal class JWKConverter : JsonConverter
    {
        // The members registered in RFC 7517 - Section 4, which are public by definition. Any other member this
        // library could not interpret may be private key material - the "d" of a key type it has no support for, for
        // example - so it is withheld from a public key export.
        private static readonly HashSet<string> RegisteredPublicMembers = new HashSet<string>
        {
            "kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256"
        };

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

            jwk.SetAdditionalMembers(CollectAdditionalMembers(jo, jwk));

            return jwk;
        }

        /// <summary>
        /// Every member which was not turned into a part of the JWK - either because this library does not know it
        /// (e.g. "x5c") or because it could not be interpreted (e.g. an unknown "kty"). Keeping the raw JSON of those
        /// members means that exporting a JWK again does not silently drop information.
        /// </summary>
        private static Dictionary<string, string> CollectAdditionalMembers(JObject jo, JWK jwk)
        {
            var consumed = new HashSet<string>();
            if (jwk.KeyType is { })
                consumed.Add("kty");
            if (jwk.PublicKeyUse is { })
                consumed.Add("use");
            if (jwk.KeyOperations is { })
                consumed.Add("key_ops");
            if (jwk.Algorithm is { })
                consumed.Add("alg");
            if (jwk.KeyID is { })
                consumed.Add("kid");
            if (jwk.KeyParameters is { })
                foreach (var keyParameter in jwk.KeyParameters.Keys)
                    consumed.Add(keyParameter.Name);

            var additionalMembers = new Dictionary<string, string>();
            foreach (var member in jo.Properties())
            {
                if (!consumed.Contains(member.Name))
                    additionalMembers.Add(member.Name, member.Value.ToString(Formatting.None));
            }

            return additionalMembers;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            if (!(value is JWK))
                throw new ArgumentException("JWK Converter can only objects serialize the type 'JWK'. Found object of type " + value.GetType() + " instead.");

            writer.WriteStartObject();

            var type = value.GetType();
            var properties = type.GetProperties(); // Get all public properties
            var members = ((JWK)value)._exportedMembers;
            var isFirstMember = true;

            foreach (var property in properties)
            {
                var propertyValue = property.GetValue(value);
                if (propertyValue is null)
                    continue;

                foreach (var customAttribute in property.CustomAttributes){

                    if (customAttribute.AttributeType != typeof(JsonPropertyAttribute))
                        break; // Only serialize fields which are marked with "JsonProperty"

                    var customJSONPropertyName = customAttribute.NamedArguments.ElementAtOrDefault(0).TypedValue.ToString();
                    var member = string.Empty;

                    var customConverterAttribute = property.CustomAttributes.FirstOrDefault(a => a.AttributeType == typeof(JWKConverterAttribute));
                    if (customConverterAttribute is { }) // Let the type handle the serialization itself as there is a custom serialization needed
                    {
                        var customConverterType = customConverterAttribute.ConstructorArguments.FirstOrDefault(a => a.ArgumentType == typeof(Type)).Value;
                        if(customConverterType is { })
                        {
                            var instance = Activator.CreateInstance(customConverterType as Type, true) as IJWKConverter;
                            member = instance.Serialize(members, propertyValue);
                        }
                    }
                    else if (propertyValue is IJWKConverter)
                        member = customJSONPropertyName + ":" + JsonConvert.ToString(((IJWKConverter)propertyValue).Serialize(members));

                    else // Serialize system types directly
                        member = customJSONPropertyName + ":" + JsonConvert.ToString(propertyValue.ToString());

                    // A converter can decide that there is nothing to write at all (e.g. a key which only has private
                    // parameters, exported as a public key). Writing a separator for it would produce invalid JSON.
                    if (member != string.Empty)
                    {
                        WriteSeparator(writer, ref isFirstMember);
                        writer.WriteRaw(member);
                    }
                }
            }

            foreach (var additionalMember in ((JWK)value).AdditionalMembers)
            {
                if (members == KeyMembers.Public && !RegisteredPublicMembers.Contains(additionalMember.Key))
                    continue;

                WriteSeparator(writer, ref isFirstMember);
                writer.WriteRaw(JsonConvert.ToString(additionalMember.Key) + ":" + additionalMember.Value);
            }

            writer.WriteEndObject();
        }

        private void WriteSeparator(JsonWriter writer, ref bool isFirstMember)
        {
            if (isFirstMember) // Don't start the JSON object with a comma
                isFirstMember = false;
            else
                writer.WriteRaw(",");
        }

    }
}
