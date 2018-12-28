using System.ComponentModel;
using CreativeCode.JWK.TypeConverters;

namespace CreativeCode.JWK.KeyParts
{
    // See RFC 7517 - JSON Web Key (JWK) - Section 4.2. "use" (Public Key Use) Parameters
    public sealed class PublicKeyUse : IJWKKeyPart
    {
        public static readonly PublicKeyUse Signature = new PublicKeyUse("sig");
        public static readonly PublicKeyUse Encryption = new PublicKeyUse("enc");

        private readonly string value;

        private PublicKeyUse(string value)
        {
            this.value = value;
        }

        public string Serialize(bool shouldExportPrivateKey = false)
        {
            return value;
        }
    }
}
