using System;

namespace CreativeCode.JWK.KeyParts
{
    // See RFC 7517 - JSON Web Key (JWK) - Section 4.3. "key_ops" (Key Operations) Parameter
    public sealed class KeyOperation
    {
        private const string SIGN_VALUE = "sign";
        private const string VERIFY_VALUE = "verify";
        private const string ENCRYPT_VALUE = "encrypt";
        private const string DECRYPT_VALUE = "decrypt";
        private const string WRAP_KEY_VALUE = "wrapKey";
        private const string UNWRAP_KEY_VALUE = "unwrapKey";
        private const string DERIVE_KEY_VALUE = "deriveKey";
        private const string DERIVE_BITS_VALUE = "deriveBits";

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

        public static KeyOperation TryGetKeyOperation(string keyOperation)
        {
            return keyOperation switch
            {
                SIGN_VALUE => ComputeDigitalSignature,
                VERIFY_VALUE => VerifyDigitalSignature,
                ENCRYPT_VALUE => EncryptContent,
                DECRYPT_VALUE => DecryptContentAndValidateDecryption,
                WRAP_KEY_VALUE => EncryptKey,
                UNWRAP_KEY_VALUE => DeriveKey,
                DERIVE_KEY_VALUE => DecryptKeyAndValidateDecryption,
                DERIVE_BITS_VALUE => DeriveBits,
                _ => null
            };
        }
    }
}
