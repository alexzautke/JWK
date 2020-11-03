using System;

namespace CreativeCode.JWK.KeyParts
{
    // See RFC 7517 - JSON Web Key (JWK) - Section 4.3. "key_ops" (Key Operations) Parameter
    public sealed class KeyOperations : IJWKKeyPart
    {
        public static readonly KeyOperations ComputeDigitalSignature = new KeyOperations("sign");
        public static readonly KeyOperations VerifyDigitalSignature = new KeyOperations("verify");
        public static readonly KeyOperations EncryptContent = new KeyOperations("encrypt");
        public static readonly KeyOperations DecryptContentAndValidateDecryption = new KeyOperations("decrypt");
        public static readonly KeyOperations EncryptKey = new KeyOperations("wrapKey");
        public static readonly KeyOperations DecryptKeyAndValidateDecryption = new KeyOperations("unwrapKey");
        public static readonly KeyOperations DeriveKey = new KeyOperations("deriveKey");
        public static readonly KeyOperations DeriveBits = new KeyOperations("deriveBits");

        private readonly string value;

        private KeyOperations(string value)
        {
            this.value = value;
        }

        public string Serialize(bool shouldExportPrivateKey = false)
        {
            return value;
        }
    }
}
