using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using CreativeCode.JWK.KeyParts;
using FluentAssertions;
using Xunit;
using static CreativeCode.JWK.KeyParts.KeyParameter;

namespace CreativeCode.JWK.Tests
{
    public class KeyConversionTests
    {
        private static readonly byte[] Content = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");

        [Theory]
        [InlineData(null, 2048)]
        [InlineData(3072, 3072)]
        public void JWKWithRSAKeyCanBeConvertedToRSAParameters(int? rsaKeySize, int expectedKeySize)
        {
            var jwk = new JWK(Algorithm.RS256, PublicKeyUse.Signature, new[] { KeyOperation.ComputeDigitalSignature }, rsaKeySize);

            jwk.GetKeySizeInBits().Should().Be(expectedKeySize);

            using var rsa = RSA.Create();
            rsa.ImportParameters(jwk.ToRSAParameters());
            rsa.KeySize.Should().Be(expectedKeySize);

            // The private key material survived the conversion if it can be verified with the public key only
            var signature = rsa.SignData(Content, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            JWK.TryParse(jwk.Export(KeyMembers.Public), out var publicKey, out _).Should().BeTrue();
            using var publicRsa = RSA.Create();
            publicRsa.ImportParameters(publicKey.ToRSAParameters());
            publicRsa.VerifyData(Content, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).Should().BeTrue();
        }

        [Theory]
        [InlineData("ES256", 256)]
        [InlineData("ES384", 384)]
        [InlineData("ES512", 521)]
        public void JWKWithECKeyCanBeConvertedToECParameters(string algorithmName, int expectedKeySize)
        {
            var algorithm = Algorithm.TryGetAlgorithm(algorithmName);
            var jwk = new JWK(algorithm, PublicKeyUse.Signature, new[] { KeyOperation.ComputeDigitalSignature });

            jwk.GetKeySizeInBits().Should().Be(expectedKeySize);

            using var eCDsa = ECDsa.Create(jwk.ToECParameters());
            var signature = eCDsa.SignData(Content, HashAlgorithmName.SHA256);

            JWK.TryParse(jwk.Export(KeyMembers.Public), out var publicKey, out _).Should().BeTrue();
            using var publicECDsa = ECDsa.Create(publicKey.ToECParameters());
            publicECDsa.VerifyData(Content, signature, HashAlgorithmName.SHA256).Should().BeTrue();
        }

        [Fact]
        public void JWKWithSymmetricKeyReportsKeySize()
        {
            var jwk = new JWK(Algorithm.A128GCMKW, PublicKeyUse.Encryption, new[] { KeyOperation.EncryptKey });

            jwk.GetKeySizeInBits().Should().Be(128);
        }

        [Fact]
        public void JWKWithWrongKeyTypeThrowsException()
        {
            var jwk = new JWK(Algorithm.RS256, PublicKeyUse.Signature, new[] { KeyOperation.ComputeDigitalSignature });

            Assert.Throws<InvalidOperationException>(() => jwk.ToECParameters());
        }

        [Fact]
        public void JWKWithIncompletePrivateRSAKeyThrowsException()
        {
            var keyParameters = new Dictionary<KeyParameter, string>
            {
                {RSAKeyParameterN, "AQAB"},
                {RSAKeyParameterE, "AQAB"},
                {RSAKeyParameterD, "AQAB"} // The CRT parameters are missing
            };
            var jwk = new JWK(KeyType.RSA, keyParameters);

            var exception = Assert.Throws<InvalidOperationException>(() => jwk.ToRSAParameters());
            exception.Message.Should().Contain("'p'").And.Contain("'qi'");
        }

        [Fact]
        public void JWKWithMultiPrimeRSAKeyThrowsException()
        {
            var jwk = new JWK("{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"oth\":[{\"r\":\"AQAB\",\"d\":\"AQAB\",\"t\":\"AQAB\"}]}");

            var exception = Assert.Throws<InvalidOperationException>(() => jwk.ToRSAParameters());
            exception.Message.Should().Contain("Multi-prime");
        }
    }
}
