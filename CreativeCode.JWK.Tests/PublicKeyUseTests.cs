using System;
using CreativeCode.JWK.KeyParts;
using System.Linq;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using Xunit;

namespace CreativeCode.JWK.Tests
{
    public class PublicKeyUseTests
    {
        [Fact]
        public void PublicKeyUseCanBeSerialized()
        {
            var use = PublicKeyUse.Signature;
            var jwk = new JWK(Algorithm.ES256, use, new[] { KeyOperation.ComputeDigitalSignature });

            JObject.Parse(jwk.Export()).GetValue("use").ToString().Should().Be(use.KeyUse, "The value of the Public Key Use Parameter should be serialized");
        }

        [Theory]
        [InlineData(typeof(Algorithm))]
        [InlineData(typeof(KeyType))]
        [InlineData(typeof(PublicKeyUse))]
        public void SerializationMembersAreNotPublicAPI(Type type)
        {
            // Serialize and Deserialize belong to the internal serialization contract, not to the public API
            type.GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)
                .Select(method => method.Name)
                .Should().NotContain(new[] { "Serialize", "Deserialize" });
        }
    }
}
