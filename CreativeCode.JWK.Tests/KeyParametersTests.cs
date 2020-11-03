using System;
using System.Collections.Generic;
using CreativeCode.JWK.KeyParts;
using FluentAssertions;
using Xunit;

namespace CreativeCode.JWK.Tests
{
    public class KeyParametersTests
    {
        [Fact]
        public void KeyParametersCanBeSerialized()
        {
            var keyParameters = new KeyParameters(new Dictionary<string, (string parameterValue, bool isPrivate)>
            {
                {"crv", ("curveName", false)},
                {"x", ("publicKeyX", false)},
                {"y", ("publicKeyY", false)},
                {"d", ("privateKeyD", true)}
            });

            var json = keyParameters.Serialize();
            json.Should().NotContain("privateKeyD", "privateKeyD is private and should not be exported by default");

            json.Should().Contain("\"y\":\"publicKeyY\"", "publicKeyY should be included by default");
            json.Should().Contain("\"x\":\"publicKeyX\"", "publicKeyX should be included by default");
            json.Should().Contain("\"crv\":\"curveName\"", "curveName should be included by default");
            json.EndsWith(',').Should().BeFalse("Tailing ',' should be trimmed");
        }

        [Fact]
        public void KeyParametersCanBeSerializedExportPrivate()
        {
            var keyParameters = new KeyParameters(new Dictionary<string, (string parameterValue, bool isPrivate)>
            {
                {"crv", ("curveName", false)},
                {"x", ("publicKeyX", false)},
                {"y", ("publicKeyY", false)},
                {"d", ("privateKeyD", true)}
            });

            var json = keyParameters.Serialize(true);
            json.Should().Contain("\"d\":\"privateKeyD\"", "privateKeyD is private and should be exported if requested");
            json.Should().Contain("\"y\":\"publicKeyY\"", "publicKeyY should be included by default");
            json.Should().Contain("\"x\":\"publicKeyX\"", "publicKeyX should be included by default");
            json.Should().Contain("\"crv\":\"curveName\"", "curveName should be included by default");
            json.EndsWith(',').Should().BeFalse("Tailing ',' should be trimmed");
        }
    }
}
