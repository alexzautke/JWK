using CreativeCode.JWK.KeyParts;
using Newtonsoft.Json;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using Xunit;

namespace CreativeCode.JWK.Tests
{
    public class AdditionalMembersTests
    {
        [Fact]
        public void JWKWithUnknownMembersRoundTrip()
        {
            var jwk = new JWK("{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"x5t#S256\":\"jL2ZB\",\"x5c\":[\"MIIBxDCCAW6gAwIBAgIB\"],\"vendorSpecific\":{\"a\":1}}");

            jwk.AdditionalMembers.Keys.Should().BeEquivalentTo(new[] { "x5t#S256", "x5c", "vendorSpecific" });

            var exported = JObject.Parse(jwk.Export(KeyMembers.All));
            exported.GetValue("x5t#S256").ToString().Should().Be("jL2ZB");
            exported.GetValue("x5c").ToString(Formatting.None).Should().Be("[\"MIIBxDCCAW6gAwIBAgIB\"]");
            exported.GetValue("vendorSpecific").ToString(Formatting.None).Should().Be("{\"a\":1}");
            exported.GetValue("n").ToString().Should().Be("AQAB");
        }

        [Fact]
        public void JWKWithUnsupportedKeyTypeRoundTrip()
        {
            var jwk = new JWK("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}");

            jwk.KeyType.Should().BeNull("this library has no support for Octet Key Pairs");

            var exported = JObject.Parse(jwk.Export(KeyMembers.All));
            exported.GetValue("kty").ToString().Should().Be("OKP");
            exported.GetValue("crv").ToString().Should().Be("Ed25519");
            exported.GetValue("x").ToString().Should().Be("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        }

        [Fact]
        public void JWKWithUnsupportedKeyTypeDoesNotExportPrivateMembers()
        {
            // An Ed25519 key (RFC 8037). This library cannot interpret it, so it cannot know that "d" is private
            var jwk = new JWK("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\"}");

            jwk.Export(KeyMembers.Public).Should().NotContain("nWGxne", "a member of a key type this library cannot interpret may be private key material");
            jwk.ToString().Should().NotContain("nWGxne", "ToString() exports the public key only");
            jwk.Export(KeyMembers.All).Should().Contain("nWGxne", "the member is still preserved for a private key export");
        }

        [Fact]
        public void JWKWithCertificateMembersExportsThemWithThePublicKey()
        {
            // The certificate members registered in RFC 7517 - Section 4 are public by definition
            var jwk = new JWK("{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"x5c\":[\"MIIBxDCCAW6gAwIBAgIB\"],\"x5t#S256\":\"jL2ZB\",\"vendorSpecific\":\"keep out\"}");

            var exported = JObject.Parse(jwk.Export(KeyMembers.Public));
            exported.GetValue("x5c").ToString(Formatting.None).Should().Be("[\"MIIBxDCCAW6gAwIBAgIB\"]");
            exported.GetValue("x5t#S256").ToString().Should().Be("jL2ZB");
            exported.TryGetValue("vendorSpecific", out _).Should().BeFalse("an unregistered member may carry private key material");
        }

        [Fact]
        public void JWKWithGeneratedKeyHasNoAdditionalMembers()
        {
            var jwk = new JWK(Algorithm.ES256, PublicKeyUse.Signature, new[] { KeyOperation.ComputeDigitalSignature });

            jwk.AdditionalMembers.Should().BeEmpty();
        }

        [Fact]
        public void KeyParametersWithOtherPrimesAreNotSerialized()
        {
            var jwk = new JWK("{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"oth\":[{\"r\":\"AQAB\",\"d\":\"AQAB\",\"t\":\"AQAB\"}]}");

            jwk.KeyParameters.Should().ContainKey(KeyParameter.RSAKeyParameterOTH);
            jwk.Export(KeyMembers.Public).Should().NotContain("oth", "the other primes of a multi-prime key are private key material");
            jwk.Export(KeyMembers.All).Should().Contain("\"oth\":[{\"r\":\"AQAB\",\"d\":\"AQAB\",\"t\":\"AQAB\"}]", "a JSON array must not be exported as a string");
        }
    }
}
