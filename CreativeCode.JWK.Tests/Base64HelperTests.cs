using FluentAssertions;
using Xunit;
using static CreativeCode.JWK.Base64Helper;

namespace CreativeCode.JWK.Tests
{
    public class Base64HelperTests
    {
        [Fact]
        public void Base64urlUIntDropsLeadingZeroOctets()
        {
            // RSAParameters pads every value to a fixed length, a Base64urlUInt uses the minimum number of octets
            Base64urlEncodeUInt(new byte[] { 0x00, 0x00, 0x01, 0x00, 0x01 }).Should().Be(Base64urlEncode(new byte[] { 0x01, 0x00, 0x01 }));
        }

        [Fact]
        public void Base64urlUIntOfZeroIsASingleZeroOctet()
        {
            Base64urlEncodeUInt(new byte[] { 0x00, 0x00 }).Should().Be(Base64urlEncode(new byte[] { 0x00 }));
        }

        [Fact]
        public void Base64urlUIntKeepsMinimalValue()
        {
            Base64urlEncodeUInt(new byte[] { 0x01, 0x00, 0x01 }).Should().Be("AQAB");
        }

        [Theory]
        [InlineData("AQAB")]      // No padding needed
        [InlineData("AQABAQ")]    // Two padding characters
        [InlineData("AQABAQA")]   // One padding character
        [InlineData("-_8")]       // The base64url specific characters
        public void ValidBase64urlCanBeDecoded(string value)
        {
            TryBase64urlDecode(value, out var decoded).Should().BeTrue();
            Base64urlEncode(decoded).Should().Be(value);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("A")]          // A length of 1 modulo 4 cannot be produced by any base64 encoder
        [InlineData("AQ==")]       // Padded, which base64url is not
        [InlineData("a+b/c")]      // Standard base64, not base64url
        [InlineData("AQ AB")]      // Convert.FromBase64String would silently ignore the whitespace
        [InlineData("AQ\nAB")]
        public void InvalidBase64urlIsRejected(string value)
        {
            TryBase64urlDecode(value, out var decoded).Should().BeFalse();
            decoded.Should().BeNull();
        }
    }
}
