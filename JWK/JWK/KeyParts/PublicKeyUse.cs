using System.ComponentModel;
using JWK.TypeConverters;

namespace JWK.KeyParts
{
    // See RFC 7517 - JSON Web Key (JWK) - Section 4.2. "use" (Public Key Use) Parameters
    [TypeConverter(typeof(ConstantConverter))]
    public sealed class PublicKeyUse
    {
        public static readonly PublicKeyUse Signature = new PublicKeyUse("sig");
        public static readonly PublicKeyUse Encryption = new PublicKeyUse("enc");

        private readonly string value;

        private PublicKeyUse(string value)
        {
            this.value = value;
        }

        public override string ToString()
        {
            return value;
        }
    }
}
