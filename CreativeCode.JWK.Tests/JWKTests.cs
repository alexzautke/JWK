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
        public void JWKWithRSA256SignatureCanBeSerialized()
        {
            JWK jwk = new JWK();
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.RS256;
            jwk.BuildWithOptions(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("n", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("e", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS256.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperations.ComputeDigitalSignature.Operations.FirstOrDefault(), KeyOperations.VerifyDigitalSignature.Operations.FirstOrDefault() });
        }

        [Fact]
        public void JWKWithRSA384SignatureCanBeSerialized()
        {
            JWK jwk = new JWK();
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.RS384;
            jwk.BuildWithOptions(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("n", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("e", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS384.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperations.ComputeDigitalSignature.Operations.FirstOrDefault(), KeyOperations.VerifyDigitalSignature.Operations.FirstOrDefault() });
        }

        [Fact]
        public void JWKWithRSA512SignatureCanBeSerialized()
        {
            JWK jwk = new JWK();
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.RS512;
            jwk.BuildWithOptions(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("n", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("e", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS512.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperations.ComputeDigitalSignature.Operations.FirstOrDefault(), KeyOperations.VerifyDigitalSignature.Operations.FirstOrDefault() });
        }


        [Fact]
        public void JWKWithECSignatureCanBeSerialized()
        {
            JWK jwk = new JWK();
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES384;
            jwk.BuildWithOptions(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);
        }
    }
}
