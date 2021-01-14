using System;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK
{
    public interface IJWKKeyPart
    {
        string Serialize(bool shouldExportPrivateKey = false);
        object Deserialize(JToken jwkRepresentation);
    }
}
