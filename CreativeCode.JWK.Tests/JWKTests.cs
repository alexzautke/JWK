using System;
using System.Linq;
using CreativeCode.JWK.KeyParts;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using Xunit;

namespace CreativeCode.JWK.Tests
{
    public class JWKTests
    {
        [Fact]
        public void JWKCanBeSerialized()
        {
            JWK jwk = new JWK();
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.RS384;
            jwk.BuildWithOptions(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export();
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var value).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out value).Should().BeTrue();
            parsedJWK.TryGetValue("use", out value).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out value).Should().BeTrue();
            parsedJWK.TryGetValue("n", out value).Should().BeTrue();
            parsedJWK.TryGetValue("e", out value).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS384.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperations.ComputeDigitalSignature.Operations.FirstOrDefault(), KeyOperations.VerifyDigitalSignature.Operations.FirstOrDefault() });

            Console.WriteLine(jwkString);
        }
    }
}
