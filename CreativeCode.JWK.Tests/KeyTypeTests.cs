using System;
using CreativeCode.JWK.KeyParts;
using FluentAssertions;
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
    }
}
