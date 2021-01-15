using System;

namespace CreativeCode.JWK.KeyParts
{
    public sealed class KeyParameter
    {
        public static readonly KeyParameter RSAKeyParameterN = new KeyParameter("n", false);
        public static readonly KeyParameter RSAKeyParameterE = new KeyParameter("e", false);
        public static readonly KeyParameter RSAKeyParameterD = new KeyParameter("d", true);
        public static readonly KeyParameter RSAKeyParameterP = new KeyParameter("p", true);
        public static readonly KeyParameter RSAKeyParameterQ = new KeyParameter("q", true);
        public static readonly KeyParameter RSAKeyParameterDP = new KeyParameter("dp", true);
        public static readonly KeyParameter RSAKeyParameterDQ = new KeyParameter("dq", true);
        public static readonly KeyParameter RSAKeyParameterQI = new KeyParameter("qi", true);

        public static readonly KeyParameter ECKeyParameterCRV = new KeyParameter("crv", false);
        public static readonly KeyParameter ECKeyParameterX = new KeyParameter("x", false);
        public static readonly KeyParameter ECKeyParameterY = new KeyParameter("y", false);
        public static readonly KeyParameter ECKeyParameterD = new KeyParameter("d", true);

        public static readonly KeyParameter OctKeyParameterK = new KeyParameter("k", true);

        public string Name { get; }
        public bool IsPrivate { get; }

        private KeyParameter(string name, bool isPrivate)
        {
            if (name == null)
                throw new ArgumentNullException("Name cannot be null");

            Name = name;
            IsPrivate = isPrivate;
        }
    }
}
