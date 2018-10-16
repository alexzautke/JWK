using System;
using JWK.KeyParts;

namespace JWK
{
    public class Startup
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Implementation of JSON Web Keys (RFC7517)");

            JWK jwk = new JWK();
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = KeyOperations.ComputeDigitalSignature;
            Algorithm algorithm = Algorithm.A128GCM;
            string jwkString = jwk.JWKfromOptions(keyUse, keyOperations, algorithm);

            Console.WriteLine(jwkString);
        }
    }
}
