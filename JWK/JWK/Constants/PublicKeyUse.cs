namespace JWK.Contants
{
    // See RFC 7517 - JSON Web Key (JWK) - Section 4.2. "use" (Public Key Use) Parameters
    public sealed class PublicKeyUse
    {
        public static readonly PublicKeyUse Signature = new PublicKeyUse(1, "sig");
        public static readonly PublicKeyUse Encryption = new PublicKeyUse(2, "enc");

        private readonly string value;
        private readonly int id;

        private PublicKeyUse(int id, string value)
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
