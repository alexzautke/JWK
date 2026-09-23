using System;
using System.Collections.Generic;
using CreativeCode.JWK.KeyParts;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using Xunit;

namespace CreativeCode.JWK.Tests
{
    public class KeyOperationTests
    {
        [Fact]
        public void JWKFromKeyParametersWithoutKeyOperationsHasNoKeyOperations()
        {
            var keyParameters = new Dictionary<KeyParameter, string> { [KeyParameter.OctKeyParameterK] = "AQAB" };

            var jwk = new JWK(KeyType.OCT, keyParameters, PublicKeyUse.Signature); // keyOperations left at its default

            jwk.KeyOperations.Should().BeNull();
            JObject.Parse(jwk.Export(KeyMembers.All)).ContainsKey("key_ops").Should().BeFalse();
        }

        [Fact]
        public void DuplicateKeyOperationsAreNotSerialized()
        {
            var keyOps = new List<KeyOperation>() { KeyOperation.ComputeDigitalSignature, KeyOperation.ComputeDigitalSignature }; // Add duplicate key_op
            var jwk = new JWK(Algorithm.RS256, PublicKeyUse.Signature, keyOps);
            var jwkString = jwk.Export(KeyMembers.All);

            var parsedJWK = JObject.Parse(jwkString);
            parsedJWK.TryGetValue("key_ops", out var token);
            token.Values<string>().Should().BeEquivalentTo(new[] { KeyOperation.ComputeDigitalSignature.Operation });
        }
    }
}
