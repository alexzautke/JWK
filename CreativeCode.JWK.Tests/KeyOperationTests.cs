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
        public void DuplicateKeyOperationsAreNotSerialized()
        {
            var keyOps = new List<KeyOperation>() { KeyOperation.ComputeDigitalSignature, KeyOperation.ComputeDigitalSignature }; // Add duplicate key_op
            var jwk = new JWK(Algorithm.RS256, PublicKeyUse.Signature, keyOps);
            var jwkString = jwk.Export(true);

            var parsedJWK = JObject.Parse(jwkString);
            parsedJWK.TryGetValue("key_ops", out var token);
            token.ToString().Should().Be($"[\n  \"{KeyOperation.ComputeDigitalSignature.Operation}\"\n]");
        }
    }
}
