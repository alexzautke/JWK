using System;

namespace CreativeCode.JWK.KeyParts
{
    // See RFC 7517 - JSON Web Key (JWK) - Section 4.2. "use" (Public Key Use) Parameters
    public sealed class PublicKeyUse : IJWKKeyPart
    {
        public static readonly PublicKeyUse Signature = new PublicKeyUse("sig");
        public static readonly PublicKeyUse Encryption = new PublicKeyUse("enc");

        public string KeyUse;

        private PublicKeyUse(string keyUse)
        {
            this.KeyUse = keyUse;
        }

        public string Serialize(bool shouldExportPrivateKey = false)
        {
            return KeyUse;
        }
    }
}
