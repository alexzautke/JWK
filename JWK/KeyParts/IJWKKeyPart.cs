using System;

namespace CreativeCode.JWK
{
    public interface IJWKKeyPart
    {
        string Serialize(bool shouldExportPrivateKey = false);
    }
}
