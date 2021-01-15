using System;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK
{
    public interface IJWKKeyPart
    {
        string Serialize(bool shouldExportPrivateKey = false, object propertyValue = null);
        object Deserialize(JToken jwkRepresentation);
        object Deserialize(JObject jwkRepresentation);
    }

    [AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
    internal class JWKConverterAttribute : Attribute
    {
        public Type @Type { get; }

        public JWKConverterAttribute() { }

        public JWKConverterAttribute(Type @Type)
        {
            this.Type = Type;
        }
    }
}
