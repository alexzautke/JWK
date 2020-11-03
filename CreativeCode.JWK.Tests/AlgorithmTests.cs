using System;
using CreativeCode.JWK.KeyParts;
using FluentAssertions;
using Xunit;

namespace CreativeCode.JWK.Tests
{
    public class AlgorithmTests
    {
        [Fact]
        public void AlgorithmShouldReturnCorrectPart()
        {
            var algorithm = Algorithm.RS384;
            algorithm.Name.Should().Be("RS384", "Name property should return the correct name of the algorithm");
            algorithm.KeyType.Should().Be(KeyType.RSA, "Name property should return the correct name of the algorithm");
        }

        [Fact]
        public void AlgorithmCanBeSerialized()
        {
            var algorithm = Algorithm.RS384;
            algorithm.Serialize().Should().Be(algorithm.Name, "The name of the algorithm should be serialized");
        }
    }
}
