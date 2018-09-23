namespace JWK.Contants
{
    // See RFC 7517 - JSON Web Key (JWK) - Section 4.3. "key_ops" (Key Operations) Parameter
    public sealed class KeyOperations
    {
        public static readonly KeyOperations ComputeDigitalSignature = new KeyOperations(1, "sign");
        public static readonly KeyOperations VerifyDigitalSignature = new KeyOperations(1, "verify");
        public static readonly KeyOperations EncryptContent = new KeyOperations(1, "encrypt");
        public static readonly KeyOperations DecryptContentAndValidateDecryption = new KeyOperations(1, "decrypt");
        public static readonly KeyOperations EncryptKey = new KeyOperations(1, "wrapKey");
        public static readonly KeyOperations DecryptKeyAndValidateDecryption = new KeyOperations(1, "unwrapKey");
        public static readonly KeyOperations DeriveKey = new KeyOperations(1, "deriveKey");
        public static readonly KeyOperations DeriveBits = new KeyOperations(1, "deriveBits");

        private readonly string value;
        private readonly int id;

        private KeyOperations(int id, string value)
        {
            this.id = id;
            this.value = value;
        }

        public override string ToString()
        {
            return value;
        }
    }
}
