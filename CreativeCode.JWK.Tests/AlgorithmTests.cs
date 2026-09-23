using System;
using CreativeCode.JWK.KeyParts;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using Xunit;

namespace CreativeCode.JWK.Tests
{
    public class AlgorithmTests
    {
        [Fact]
        public void AlgorithmCanBeSerialized()
        {
            var algorithm = Algorithm.RS384;
            var jwk = new JWK(algorithm, PublicKeyUse.Signature, new[] { KeyOperation.ComputeDigitalSignature });

            JObject.Parse(jwk.Export()).GetValue("alg").ToString().Should().Be(algorithm.Name, "The name of the algorithm should be serialized");
        }

        [Theory]
        [InlineData("RS256")]
        [InlineData("PS256")]
        [InlineData("PS384")]
        [InlineData("PS512")]
        [InlineData("ES512")]
        [InlineData("none")]
        public void AlgorithmWithRegisteredNameIsRecognized(string algorithmName)
        {
            var algorithm = Algorithm.TryGetAlgorithm(algorithmName);

            algorithm.IsRecognized.Should().BeTrue();
            algorithm.Name.Should().Be(algorithmName);
        }

        [Fact]
        public void AlgorithmWithUnknownNameKeepsItsName()
        {
            var algorithm = Algorithm.TryGetAlgorithm("EdDSA");

            algorithm.Should().NotBeNull("an unknown algorithm must not be indistinguishable from an absent one");
            algorithm.IsRecognized.Should().BeFalse();
            algorithm.Name.Should().Be("EdDSA");
        }

        [Fact]
        public void AlgorithmWithoutNameIsNull()
        {
            Algorithm.TryGetAlgorithm(null).Should().BeNull();
            Algorithm.TryGetAlgorithm("").Should().BeNull();
        }

        [Theory]
        [InlineData("PS256")] // Registered, but this library cannot create a key for it
        [InlineData("EdDSA")] // Not registered at all
        public void JWKWithUnsupportedAlgorithmRoundTrip(string algorithmName)
        {
            var jwk = new JWK(Algorithm.ES256, PublicKeyUse.Signature, new[] { KeyOperation.ComputeDigitalSignature });
            var exported = JObject.Parse(jwk.Export(KeyMembers.Public));
            exported["alg"] = algorithmName;

            var roundTripped = JObject.Parse(new JWK(exported.ToString()).Export(KeyMembers.Public));

            roundTripped.GetValue("alg").ToString().Should().Be(algorithmName);
        }

        [Fact]
        public void JWKWithUnsupportedAlgorithmThrowsException()
        {
            Assert.Throws<ArgumentException>(() => new JWK(Algorithm.PS256, PublicKeyUse.Signature));
            Assert.Throws<ArgumentException>(() => new JWK(Algorithm.None, PublicKeyUse.Signature));
            Assert.Throws<ArgumentException>(() => new JWK(Algorithm.TryGetAlgorithm("EdDSA"), PublicKeyUse.Signature));
        }
    }
}
