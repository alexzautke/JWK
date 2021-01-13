using System;
using System.Collections.Generic;
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
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.RS256;
            JWK jwk = new JWK(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("n", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("e", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("p", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("q", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dq", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dp", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("qi", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS256.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperations.ComputeDigitalSignature.Operations.FirstOrDefault(), KeyOperations.VerifyDigitalSignature.Operations.FirstOrDefault() });
        }

        [Fact]
        public void JWKWithRSA384SignatureCanBeSerialized()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.RS384;
            JWK jwk = new JWK(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("n", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("e", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("p", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("q", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dq", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dp", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("qi", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS384.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperations.ComputeDigitalSignature.Operations.FirstOrDefault(), KeyOperations.VerifyDigitalSignature.Operations.FirstOrDefault() });
        }

        [Fact]
        public void JWKWithRSA512SignatureCanBeSerialized()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.RS512;
            JWK jwk = new JWK(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("n", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("e", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("p", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("q", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dq", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dp", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("qi", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS512.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperations.ComputeDigitalSignature.Operations.FirstOrDefault(), KeyOperations.VerifyDigitalSignature.Operations.FirstOrDefault() });
        }

        [Fact]
        public void JWKCheckRSAPrivateKeyParametersExport()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.RS384;
            JWK jwk = new JWK(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export(false);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("n", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("e", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeFalse();
            parsedJWK.TryGetValue("p", out var _).Should().BeFalse();
            parsedJWK.TryGetValue("q", out var _).Should().BeFalse();
            parsedJWK.TryGetValue("dq", out var _).Should().BeFalse();
            parsedJWK.TryGetValue("dp", out var _).Should().BeFalse();
            parsedJWK.TryGetValue("qi", out var _).Should().BeFalse();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS384.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperations.ComputeDigitalSignature.Operations.FirstOrDefault(), KeyOperations.VerifyDigitalSignature.Operations.FirstOrDefault() });
        }

        [Fact]
        public void JWKWithEC256SignatureCanBeSerialized()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES256;
            JWK jwk = new JWK(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("crv", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("x", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("y", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("EC");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.ES256.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperations.ComputeDigitalSignature.Operations.FirstOrDefault(), KeyOperations.VerifyDigitalSignature.Operations.FirstOrDefault() });
        }

        [Fact]
        public void JWKWithEC384SignatureCanBeSerialized()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES384;
            JWK jwk = new JWK(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("crv", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("x", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("y", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("EC");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.ES384.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperations.ComputeDigitalSignature.Operations.FirstOrDefault(), KeyOperations.VerifyDigitalSignature.Operations.FirstOrDefault() });
        }

        [Fact]
        public void JWKWithEC512SignatureCanBeSerialized()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES512;
            JWK jwk = new JWK(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("crv", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("x", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("y", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("EC");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.ES512.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperations.ComputeDigitalSignature.Operations.FirstOrDefault(), KeyOperations.VerifyDigitalSignature.Operations.FirstOrDefault() });
        }

        [Fact]
        public void JWKCheckECPrivateKeyParametersExport()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES256;
            JWK jwk = new JWK(keyUse, keyOperations, algorithm);

            string jwkString = jwk.Export(false);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("crv", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("x", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("y", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeFalse();

            parsedJWK.GetValue("kty").ToString().Should().Be("EC");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.ES256.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperations.ComputeDigitalSignature.Operations.FirstOrDefault(), KeyOperations.VerifyDigitalSignature.Operations.FirstOrDefault() });
        }


        [Fact]
        public void JWKWithAESKeyParametersCanBeCreated()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES256;
            KeyParameters keyParameters = new KeyParameters(new Dictionary<string, (string parameterValue, bool isPrivate)>
                {
                    {"n", ("modulus", false)},
                    {"e", ("exponent", false)},
                    {"d", ("privateExponent", true)},
                    {"p", ("firstPrimeFactor", true)},
                    {"q", ("secondPrimeFactor", true)},
                    {"dp", ("firstFactorCRTExponent", true)},
                    {"dq", ("secondFactorCRTExponent", true)},
                    {"qi", ("firstCRTCoefficient", true)}
                });
            JWK jwk = new JWK(keyUse, keyOperations, algorithm, keyParameters);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.GetValue("n").ToString().Should().Be(keyParameters.Values["n"].parameterValue);
            parsedJWK.GetValue("e").ToString().Should().Be(keyParameters.Values["e"].parameterValue);
            parsedJWK.GetValue("d").ToString().Should().Be(keyParameters.Values["d"].parameterValue);
            parsedJWK.GetValue("p").ToString().Should().Be(keyParameters.Values["p"].parameterValue);
            parsedJWK.GetValue("q").ToString().Should().Be(keyParameters.Values["q"].parameterValue);
            parsedJWK.GetValue("dp").ToString().Should().Be(keyParameters.Values["dp"].parameterValue);
            parsedJWK.GetValue("dq").ToString().Should().Be(keyParameters.Values["dq"].parameterValue);
            parsedJWK.GetValue("qi").ToString().Should().Be(keyParameters.Values["qi"].parameterValue);
        }

        [Fact]
        public void JWKWithECKeyParametersCanBeCreated()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            KeyOperations keyOperations = new KeyOperations(new[] { KeyOperations.ComputeDigitalSignature, KeyOperations.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES256;
            KeyParameters keyParameters = new KeyParameters(new Dictionary<string, (string parameterValue, bool isPrivate)>
            {
                {"crv", ("curveName", false)},
                {"x", ("publicKeyX", false)},
                {"y", ("publicKeyY", false)},
                {"d", ("privateKeyD", true)}
            });
            JWK jwk = new JWK(keyUse, keyOperations, algorithm, keyParameters);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.GetValue("crv").ToString().Should().Be(keyParameters.Values["crv"].parameterValue);
            parsedJWK.GetValue("x").ToString().Should().Be(keyParameters.Values["x"].parameterValue);
            parsedJWK.GetValue("y").ToString().Should().Be(keyParameters.Values["y"].parameterValue);
            parsedJWK.GetValue("d").ToString().Should().Be(keyParameters.Values["d"].parameterValue);
        }
    }
}
