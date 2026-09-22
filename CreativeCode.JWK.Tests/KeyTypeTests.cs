using System;
using CreativeCode.JWK.KeyParts;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using Xunit;

namespace CreativeCode.JWK.Tests
{
    public class KeyTypeTests
    {
        [Fact]
        public void PublicKeyUseCanBeSerialized()
        {
            var keyType = KeyType.RSA;
            keyType.Serialize().Should().Be(keyType.Type, "The value of the Public Key Use Parameter should be serialized");
        }

        [Fact]
        public void KeyTypeOctIsSpelledAsRegistered()
        {
            KeyType.OCT.Type.Should().Be("oct", "RFC 7518 - Section 6.1 registers the octet sequence key type as 'oct'");
        }

        [Theory]
        [InlineData("oct")]
        [InlineData("OCT")] // The spelling used by this library up to and including 0.7.1
        public void KeyTypeOctCanBeReadInBothSpellings(string keyType)
        {
            KeyType.TryGetKeyType(keyType).Should().Be(KeyType.OCT);
        }

        [Fact]
        public void JWKWithSymmetricKeyIsExportedAsOct()
        {
            var jwk = new JWK(Algorithm.HS256, PublicKeyUse.Signature, new[] { KeyOperation.ComputeDigitalSignature });

            JObject.Parse(jwk.Export(KeyMembers.All)).GetValue("kty").ToString().Should().Be("oct");
        }

        [Fact]
        public void JWKWithLegacyOctSpellingCanBeDeserialized()
        {
            var jwk = new JWK("{\"kty\":\"OCT\",\"k\":\"AQAB\"}");

            jwk.KeyType.Should().Be(KeyType.OCT);
            jwk.IsSymmetric().Should().BeTrue();
            jwk.KeyParameters.Should().ContainKey(KeyParameter.OctKeyParameterK);
        }

        [Fact]
        public void KeyTypeWithUnknownNameIsNull()
        {
            KeyType.TryGetKeyType("OKP").Should().BeNull();
        }
    }
}
