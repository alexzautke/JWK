namespace CreativeCode.JWK
{
    /// <summary>
    /// Which members of a key an export writes.
    /// </summary>
    public enum KeyMembers
    {
        /// <summary>
        /// Only the members which are safe to hand out: the key parameters which are public for the key type, and the
        /// members registered in RFC 7517 - Section 4. A member this library could not interpret is withheld, because
        /// it cannot be known whether it carries private key material.
        /// </summary>
        Public,

        /// <summary>
        /// Every member of the key, including its private key material.
        /// </summary>
        All
    }
}
