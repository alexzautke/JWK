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

        /// <summary>
        /// False if this operation is not one of the operations registered in RFC 7517. The value is still preserved
        /// (and exported again) so that a JWK is not silently altered by a round trip.
        /// </summary>
        public bool IsRecognized { get; }

        private KeyOperation() { } // Used only for deserialization

        private KeyOperation(string operation) : this(operation, true) { }

        private KeyOperation(string operation, bool isRecognized)
        {
            Operation = operation;
            IsRecognized = isRecognized;
        }

        /// <summary>
        /// Returns the operation with the given name. An operation which is not registered in RFC 7517 is returned as
        /// an instance with <see cref="IsRecognized"/> set to false instead of null. Returns null only if
        /// <paramref name="keyOperation"/> is null or empty.
        /// </summary>
        public static KeyOperation TryGetKeyOperation(string keyOperation)
        {
            return keyOperation switch
            {
                SIGN_VALUE => ComputeDigitalSignature,
                VERIFY_VALUE => VerifyDigitalSignature,
                ENCRYPT_VALUE => EncryptContent,
                DECRYPT_VALUE => DecryptContentAndValidateDecryption,
                WRAP_KEY_VALUE => EncryptKey,
                UNWRAP_KEY_VALUE => DecryptKeyAndValidateDecryption,
                DERIVE_KEY_VALUE => DeriveKey,
                DERIVE_BITS_VALUE => DeriveBits,

                null => null,
                "" => null,

                _ => new KeyOperation(keyOperation, false)
            };
        }

        public override bool Equals(object obj)
        {
            return obj is KeyOperation other && Operation == other.Operation;
        }

        public override int GetHashCode()
        {
            return Operation is null ? 0 : Operation.GetHashCode();
        }

        public override string ToString()
        {
            return Operation;
        }
    }
}
