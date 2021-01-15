using System;

namespace CreativeCode.JWK.KeyParts
{
    // See RFC 7517 - JSON Web Key (JWK) - Section 4.3. "key_ops" (Key Operations) Parameter
    public sealed class KeyOperation
    {
        internal const string SIGN_VALUE = "sign";
        internal const string VERIFY_VALUE = "verify";
        internal const string ENCRYPT_VALUE = "encrypt";
        internal const string DECRYPT_VALUE = "decrypt";
        internal const string WRAP_KEY_VALUE = "wrapKey";
        internal const string UNWRAP_KEY_VALUE = "unwrapKey";
        internal const string DERIVE_KEY_VALUE = "deriveKey";
        internal const string DERIVE_BITS_VALUE = "deriveBits";

        public static readonly KeyOperation ComputeDigitalSignature = new KeyOperation(SIGN_VALUE);
        public static readonly KeyOperation VerifyDigitalSignature = new KeyOperation(VERIFY_VALUE);
        public static readonly KeyOperation EncryptContent = new KeyOperation(ENCRYPT_VALUE);
        public static readonly KeyOperation DecryptContentAndValidateDecryption = new KeyOperation(DECRYPT_VALUE);
        public static readonly KeyOperation EncryptKey = new KeyOperation(WRAP_KEY_VALUE);
        public static readonly KeyOperation DecryptKeyAndValidateDecryption = new KeyOperation(UNWRAP_KEY_VALUE);
        public static readonly KeyOperation DeriveKey = new KeyOperation(DERIVE_KEY_VALUE);
        public static readonly KeyOperation DeriveBits = new KeyOperation(DERIVE_BITS_VALUE);

        public string Operation { get; }

        private KeyOperation() { } // Used only for deserialization

        private KeyOperation(string operation)
        {
            Operation = operation;
        }
    }
}
