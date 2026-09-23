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
        public void KeyTypeCanBeSerialized()
        {
            var keyType = KeyType.RSA;
            var jwk = new JWK(Algorithm.RS256, PublicKeyUse.Signature, new[] { KeyOperation.ComputeDigitalSignature });

            JObject.Parse(jwk.Export()).GetValue("kty").ToString().Should().Be(keyType.Type, "The value of the Key Type Parameter should be serialized");
        }

        [Fact]
        public void KeyTypeOctIsSpelledAsRegistered()
        {
            KeyType.OCT.Type.Should().Be("oct", "RFC 7518 - Section 6.1 registers the octet sequence key type as 'oct'");
        }

        [Fact]
        public void KeyTypeOctIsOnlyReadInItsRegisteredSpelling()
        {
            KeyType.TryGetKeyType("oct").Should().Be(KeyType.OCT);
            KeyType.TryGetKeyType("OCT").Should().BeNull("'OCT' is the unregistered spelling used by this library up to and including 0.7.1");
        }

        [Fact]
        public void JWKWithSymmetricKeyIsExportedAsOct()
        {
            var jwk = new JWK(Algorithm.HS256, PublicKeyUse.Signature, new[] { KeyOperation.ComputeDigitalSignature });

            JObject.Parse(jwk.Export(KeyMembers.All)).GetValue("kty").ToString().Should().Be("oct");
        }

        [Fact]
        public void JWKWithLegacyOctSpellingIsReadAsKeyOfUnsupportedKeyType()
        {
            // "OCT" is the unregistered spelling this library used up to and including 0.7.1. It is no longer read as
            // "oct": the key has no key type and its members are only kept as additional members.
            var jwk = new JWK("{\"kty\":\"OCT\",\"k\":\"AQAB\"}");

            jwk.KeyType.Should().BeNull();
            jwk.KeyParameters.Should().BeNullOrEmpty();
            jwk.AdditionalMembers.Should().ContainKey("k");
        }

        [Fact]
        public void KeyTypeWithUnknownNameIsNull()
        {
            KeyType.TryGetKeyType("OKP").Should().BeNull();
        }
    }
}
