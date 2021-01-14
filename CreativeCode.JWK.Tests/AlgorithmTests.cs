using System;
using CreativeCode.JWK.KeyParts;
using FluentAssertions;
using Xunit;

namespace CreativeCode.JWK.Tests
{
    public class AlgorithmTests
    {
        [Fact]
        public void AlgorithmCanBeSerialized()
        {
            var algorithm = Algorithm.RS384;
            algorithm.Serialize().Should().Be(algorithm.Name, "The name of the algorithm should be serialized");
        }
    }
}
