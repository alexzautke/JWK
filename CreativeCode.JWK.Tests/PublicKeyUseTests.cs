using System;
using CreativeCode.JWK.KeyParts;
using FluentAssertions;
using Xunit;

namespace CreativeCode.JWK.Tests
{
    public class PublicKeyUseTests
    {
        [Fact]
        public void PublicKeyUseCanBeSerialized()
        {
            var use = PublicKeyUse.Signature;
            use.Serialize().Should().Be(use.KeyUse, "The value of the Public Key Use Parameter should be serialized");
        }
    }
}
