using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CreativeCode.JWK.KeyParts;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using Xunit;
using static CreativeCode.JWK.KeyParts.KeyParameter;
using static CreativeCode.JWK.Base64Helper;

namespace CreativeCode.JWK.Tests
{
    public class JWKTests
    {
        [Fact]
        public void JWKWithRSA256SignatureCanBeSerialized()
        {
            var keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            var algorithm = Algorithm.RS256;
            var jwk = new JWK(algorithm, keyUse, keyOperations);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("n", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("e", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("p", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("q", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dq", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dp", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("qi", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS256.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation });
        }

        [Fact]
        public void JWKWithRSA384SignatureCanBeSerialized()
        {
            var keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            var algorithm = Algorithm.RS384;
            var jwk = new JWK(algorithm, keyUse, keyOperations);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("n", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("e", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("p", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("q", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dq", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dp", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("qi", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS384.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation });
        }

        [Fact]
        public void JWKWithRSA512SignatureCanBeSerialized()
        {
            var keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            var algorithm = Algorithm.RS512;
            var jwk = new JWK(algorithm, keyUse, keyOperations);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("n", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("e", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("p", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("q", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dq", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dp", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("qi", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS512.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation });
        }

        [Fact]
        public void JWKCheckRSAPrivateKeyParametersExport()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.RS384;
            JWK jwk = new JWK(algorithm, keyUse, keyOperations);

            string jwkString = jwk.Export(false);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("n", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("e", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeFalse();
            parsedJWK.TryGetValue("p", out var _).Should().BeFalse();
            parsedJWK.TryGetValue("q", out var _).Should().BeFalse();
            parsedJWK.TryGetValue("dq", out var _).Should().BeFalse();
            parsedJWK.TryGetValue("dp", out var _).Should().BeFalse();
            parsedJWK.TryGetValue("qi", out var _).Should().BeFalse();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS384.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation });
        }

        [Fact]
        public void JWKWithEC256SignatureCanBeSerialized()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES256;
            JWK jwk = new JWK(algorithm, keyUse, keyOperations);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("crv", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("x", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("y", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("EC");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.ES256.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation });
        }

        [Fact]
        public void JWKWithEC384SignatureCanBeSerialized()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES384;
            JWK jwk = new JWK(algorithm, keyUse, keyOperations);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("crv", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("x", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("y", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("EC");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.ES384.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation });
        }

        [Fact]
        public void JWKWithEC512SignatureCanBeSerialized()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES512;
            JWK jwk = new JWK(algorithm, keyUse, keyOperations);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("crv", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("x", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("y", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("EC");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.ES512.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation });
        }

        [Fact]
        public void JWKCheckECPrivateKeyParametersExport()
        {
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES256;
            JWK jwk = new JWK(algorithm, keyUse, keyOperations);

            string jwkString = jwk.Export(false);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("crv", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("x", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("y", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeFalse();

            parsedJWK.GetValue("kty").ToString().Should().Be("EC");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.ES256.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation });
        }


        [Fact]
        public void JWKWithAESKeyParametersCanBeCreated()
        {
            KeyType keyType = KeyType.RSA;
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES256;
            var keyParameters = new Dictionary<KeyParameter, string>
                {
                    {RSAKeyParameterN, "modulus"},
                    {RSAKeyParameterE, "exponent"},
                    {RSAKeyParameterD, "privateExponent"},
                    {RSAKeyParameterP, "firstPrimeFactor"},
                    {RSAKeyParameterQ, "secondPrimeFactor"},
                    {RSAKeyParameterDP, "firstFactorCRTExponent"},
                    {RSAKeyParameterDQ, "secondFactorCRTExponent"},
                    {RSAKeyParameterQI, "firstCRTCoefficient"}
                };
            JWK jwk = new JWK(keyType, keyParameters, keyUse, keyOperations, algorithm, "test");

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.GetValue("n").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterN));
            parsedJWK.GetValue("e").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterE));
            parsedJWK.GetValue("d").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterD));
            parsedJWK.GetValue("p").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterP));
            parsedJWK.GetValue("q").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterQ));
            parsedJWK.GetValue("dp").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterDP));
            parsedJWK.GetValue("dq").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterDQ));
            parsedJWK.GetValue("qi").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterQI));
            parsedJWK.GetValue("kid").ToString().Should().Be("test");
        }

        [Fact]
        public void JWKWithECKeyParametersCanBeCreated()
        {
            KeyType keyType = KeyType.EllipticCurve;
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES256;
            var keyParameters = new Dictionary<KeyParameter, string>
            {
                {ECKeyParameterCRV, "curveName"},
                {ECKeyParameterX, "publicKeyX"},
                {ECKeyParameterY, "publicKeyY"},
                {ECKeyParameterD, "privateKeyD"}
            };
            JWK jwk = new JWK(keyType, keyParameters, keyUse, keyOperations, algorithm, "test");

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.GetValue("crv").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterCRV));
            parsedJWK.GetValue("x").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterX));
            parsedJWK.GetValue("y").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterY));
            parsedJWK.GetValue("d").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterD));
            parsedJWK.GetValue("kid").ToString().Should().Be("test");
        }

        [Fact]
        public void JWKCanBeDeserialized()
        {
            var jwk = new JWK("{\"kty\":\"RSA\",\"use\":\"sig\",\"key_ops\":[\"sign\",\"verify\"],\"alg\":\"RS256\",\"kid\":\"e9515a90-7479-4ff8-a3b1-23aaef3b5675\",\"n\":\"4W_ciNjvogFBPf9BYd9jySsrsN6gdosZMAWDi79bZIpYXPHSynbNQUcDe2tSwGKgG9d1ak-jLtZ37SOcC0s1C6W5jAGBHuA-2Oscpa1DZPXrShrDW0wbO2wbBW17pY9rLlnFel-26eE48U0utDdDFCxBBOsWj382sDJzfqLj6DTKBn9r1wDvbRLbWecvZF5uTG392KoO5sNvwwnAhRzo1HX7hPTr5zDOBkfKQolIo99g5Gq9k-_yqDWmRC0mxO6SOfFdrxSMTgCUTyZA_jQXvn7OrSO28yvKdpnrHihGExHubA-m30a21LBQlomovYZiXJ7mlvUnzFxxa7XOsbA1sFU\",\"e\":\"AQAB\",\"d\":\"BAOo6qrqQXlCPydfc621qixhn8mnE9VQQoGmoQNsTjMEdcs8lKxe5U2tazIzDAf1j-lbRuRaJIhfJFLhAXZ6YFW4Ix0XvoQBun0dSnn2XELgyLYHSoXlaj53kLYtYHpYTz_7-zzfFfUTvYBBV6YwRJixI7RH95AtWh_b3KJr6oOdmGzul7XcHJ0rcPAKfRXhUrDpjS-iZ3TOAEImQHBwHCjsiQPSDlz3jlUlG-LnE9l3PH49rKFjwc6RIfhKt0jBuwnxE3cX87ux-cFBdo_lIyv2yH-watb9SO1WqxQA2rXBXrWWKitLMhaQLFdHIZEf1lHN7VA_UD9ty9p8CZC21NU\",\"p\":\"D0X1M5HmLBNMSvxA_uF-KQ2YnhDmt4ldHiKLjjpJnvJLwXf-TDbApIfHnkRnHxd9adLO4IaAlqL3_oVlS1ZuEijy6auzfwbrcgfsuEYR_k7fG4T8K9TDS2FWe24xFkJgVdRpuMiAt0wZZEexCv2oIFDM0idXrUl7Ikq6RL3kOwob\",\"q\":\"DsKeLZl2Du2RBszDDWKMYhORGR93-CPhSGZT91-Dic6iSWtumfIGAbkjEFiCeMs4tJwktgiYS76IsQ9qCZdrcBj2h-LgMUqrdqKmSq2-krsQPpJxfPadHewa8T2_e48wXzxmx8Dmmoqd4q1LPbOHFMJpY2HBwXopeIbtFa1vUdZP\",\"dp\":\"DDNG5nXyVlzoAbI1PSTlQWfx9LntgskAkDTqI6fd7VEBQL9YbIsEIamwxHVBpq196g2SYfovN6Vg0ni-bIrTDECXoh8dGChv5Tv9VUnrz6gzQmldgqnHgyxzB9AC-BP3njg6Z3gKkeEBG4DFJNFw_rdslacFu4_KA5-L4aOKb7rn\",\"dq\":\"Dmzw0Rohwvc1_VJT85n0H8qFzerugkr2255-w87KrP2RqHXh830Rl8-MUGZgpZPgSMwuKOZ_ic-eooWxGcyuSTFsiGQYvrP-ngTaxzPFhHxkpPLVDc-swNjHgCzcHvNT0FAlF2cVOcbuBeNeHOB_za8v9txM1D4Dl_MudTg7Ct2L\",\"qi\":\"Aw3In2d6QWQ95rRJwAVAXuWJKubLqSxXTPVu7ueyn1PGMyzK7-6nFNfa1WBpCE4LQ-Ep3eZ2GhSZzN888iixnkNNuaXToUzk0dBEyNM7WDg8tGuyvd5yaJd6wj8q6prYUJGxk7V0mDMhSsA6uttRYe9rbemye6eUNwQIvfmjkbQl\"}");
            jwk.KeyType.Should().Be(KeyType.RSA);
            jwk.PublicKeyUse.Should().Be(PublicKeyUse.Signature);
            jwk.KeyOperations.Should().BeEquivalentTo(new HashSet<KeyOperation>() { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
            jwk.Algorithm.Should().Be(Algorithm.RS256);
            jwk.KeyID.Should().Be("e9515a90-7479-4ff8-a3b1-23aaef3b5675");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterN).Should().Be("4W_ciNjvogFBPf9BYd9jySsrsN6gdosZMAWDi79bZIpYXPHSynbNQUcDe2tSwGKgG9d1ak-jLtZ37SOcC0s1C6W5jAGBHuA-2Oscpa1DZPXrShrDW0wbO2wbBW17pY9rLlnFel-26eE48U0utDdDFCxBBOsWj382sDJzfqLj6DTKBn9r1wDvbRLbWecvZF5uTG392KoO5sNvwwnAhRzo1HX7hPTr5zDOBkfKQolIo99g5Gq9k-_yqDWmRC0mxO6SOfFdrxSMTgCUTyZA_jQXvn7OrSO28yvKdpnrHihGExHubA-m30a21LBQlomovYZiXJ7mlvUnzFxxa7XOsbA1sFU");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterE).Should().Be("AQAB");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterD).Should().Be("BAOo6qrqQXlCPydfc621qixhn8mnE9VQQoGmoQNsTjMEdcs8lKxe5U2tazIzDAf1j-lbRuRaJIhfJFLhAXZ6YFW4Ix0XvoQBun0dSnn2XELgyLYHSoXlaj53kLYtYHpYTz_7-zzfFfUTvYBBV6YwRJixI7RH95AtWh_b3KJr6oOdmGzul7XcHJ0rcPAKfRXhUrDpjS-iZ3TOAEImQHBwHCjsiQPSDlz3jlUlG-LnE9l3PH49rKFjwc6RIfhKt0jBuwnxE3cX87ux-cFBdo_lIyv2yH-watb9SO1WqxQA2rXBXrWWKitLMhaQLFdHIZEf1lHN7VA_UD9ty9p8CZC21NU");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterP).Should().Be("D0X1M5HmLBNMSvxA_uF-KQ2YnhDmt4ldHiKLjjpJnvJLwXf-TDbApIfHnkRnHxd9adLO4IaAlqL3_oVlS1ZuEijy6auzfwbrcgfsuEYR_k7fG4T8K9TDS2FWe24xFkJgVdRpuMiAt0wZZEexCv2oIFDM0idXrUl7Ikq6RL3kOwob");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterQ).Should().Be("DsKeLZl2Du2RBszDDWKMYhORGR93-CPhSGZT91-Dic6iSWtumfIGAbkjEFiCeMs4tJwktgiYS76IsQ9qCZdrcBj2h-LgMUqrdqKmSq2-krsQPpJxfPadHewa8T2_e48wXzxmx8Dmmoqd4q1LPbOHFMJpY2HBwXopeIbtFa1vUdZP");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterDP).Should().Be("DDNG5nXyVlzoAbI1PSTlQWfx9LntgskAkDTqI6fd7VEBQL9YbIsEIamwxHVBpq196g2SYfovN6Vg0ni-bIrTDECXoh8dGChv5Tv9VUnrz6gzQmldgqnHgyxzB9AC-BP3njg6Z3gKkeEBG4DFJNFw_rdslacFu4_KA5-L4aOKb7rn");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterDQ).Should().Be("Dmzw0Rohwvc1_VJT85n0H8qFzerugkr2255-w87KrP2RqHXh830Rl8-MUGZgpZPgSMwuKOZ_ic-eooWxGcyuSTFsiGQYvrP-ngTaxzPFhHxkpPLVDc-swNjHgCzcHvNT0FAlF2cVOcbuBeNeHOB_za8v9txM1D4Dl_MudTg7Ct2L");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterQI).Should().Be("Aw3In2d6QWQ95rRJwAVAXuWJKubLqSxXTPVu7ueyn1PGMyzK7-6nFNfa1WBpCE4LQ-Ep3eZ2GhSZzN888iixnkNNuaXToUzk0dBEyNM7WDg8tGuyvd5yaJd6wj8q6prYUJGxk7V0mDMhSsA6uttRYe9rbemye6eUNwQIvfmjkbQl");
        }

        [Fact]
        public void JWKCanBeDeserializedMinimalElements()
        {
            var jwk = new JWK("{\"kty\":\"RSA\",\"n\":\"4W_ciNjvogFBPf9BYd9jySsrsN6gdosZMAWDi79bZIpYXPHSynbNQUcDe2tSwGKgG9d1ak-jLtZ37SOcC0s1C6W5jAGBHuA-2Oscpa1DZPXrShrDW0wbO2wbBW17pY9rLlnFel-26eE48U0utDdDFCxBBOsWj382sDJzfqLj6DTKBn9r1wDvbRLbWecvZF5uTG392KoO5sNvwwnAhRzo1HX7hPTr5zDOBkfKQolIo99g5Gq9k-_yqDWmRC0mxO6SOfFdrxSMTgCUTyZA_jQXvn7OrSO28yvKdpnrHihGExHubA-m30a21LBQlomovYZiXJ7mlvUnzFxxa7XOsbA1sFU\",\"e\":\"AQAB\",\"d\":\"BAOo6qrqQXlCPydfc621qixhn8mnE9VQQoGmoQNsTjMEdcs8lKxe5U2tazIzDAf1j-lbRuRaJIhfJFLhAXZ6YFW4Ix0XvoQBun0dSnn2XELgyLYHSoXlaj53kLYtYHpYTz_7-zzfFfUTvYBBV6YwRJixI7RH95AtWh_b3KJr6oOdmGzul7XcHJ0rcPAKfRXhUrDpjS-iZ3TOAEImQHBwHCjsiQPSDlz3jlUlG-LnE9l3PH49rKFjwc6RIfhKt0jBuwnxE3cX87ux-cFBdo_lIyv2yH-watb9SO1WqxQA2rXBXrWWKitLMhaQLFdHIZEf1lHN7VA_UD9ty9p8CZC21NU\",\"p\":\"D0X1M5HmLBNMSvxA_uF-KQ2YnhDmt4ldHiKLjjpJnvJLwXf-TDbApIfHnkRnHxd9adLO4IaAlqL3_oVlS1ZuEijy6auzfwbrcgfsuEYR_k7fG4T8K9TDS2FWe24xFkJgVdRpuMiAt0wZZEexCv2oIFDM0idXrUl7Ikq6RL3kOwob\",\"q\":\"DsKeLZl2Du2RBszDDWKMYhORGR93-CPhSGZT91-Dic6iSWtumfIGAbkjEFiCeMs4tJwktgiYS76IsQ9qCZdrcBj2h-LgMUqrdqKmSq2-krsQPpJxfPadHewa8T2_e48wXzxmx8Dmmoqd4q1LPbOHFMJpY2HBwXopeIbtFa1vUdZP\",\"dp\":\"DDNG5nXyVlzoAbI1PSTlQWfx9LntgskAkDTqI6fd7VEBQL9YbIsEIamwxHVBpq196g2SYfovN6Vg0ni-bIrTDECXoh8dGChv5Tv9VUnrz6gzQmldgqnHgyxzB9AC-BP3njg6Z3gKkeEBG4DFJNFw_rdslacFu4_KA5-L4aOKb7rn\",\"dq\":\"Dmzw0Rohwvc1_VJT85n0H8qFzerugkr2255-w87KrP2RqHXh830Rl8-MUGZgpZPgSMwuKOZ_ic-eooWxGcyuSTFsiGQYvrP-ngTaxzPFhHxkpPLVDc-swNjHgCzcHvNT0FAlF2cVOcbuBeNeHOB_za8v9txM1D4Dl_MudTg7Ct2L\",\"qi\":\"Aw3In2d6QWQ95rRJwAVAXuWJKubLqSxXTPVu7ueyn1PGMyzK7-6nFNfa1WBpCE4LQ-Ep3eZ2GhSZzN888iixnkNNuaXToUzk0dBEyNM7WDg8tGuyvd5yaJd6wj8q6prYUJGxk7V0mDMhSsA6uttRYe9rbemye6eUNwQIvfmjkbQl\"}");
            jwk.KeyType.Should().Be(KeyType.RSA);
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterN).Should().Be("4W_ciNjvogFBPf9BYd9jySsrsN6gdosZMAWDi79bZIpYXPHSynbNQUcDe2tSwGKgG9d1ak-jLtZ37SOcC0s1C6W5jAGBHuA-2Oscpa1DZPXrShrDW0wbO2wbBW17pY9rLlnFel-26eE48U0utDdDFCxBBOsWj382sDJzfqLj6DTKBn9r1wDvbRLbWecvZF5uTG392KoO5sNvwwnAhRzo1HX7hPTr5zDOBkfKQolIo99g5Gq9k-_yqDWmRC0mxO6SOfFdrxSMTgCUTyZA_jQXvn7OrSO28yvKdpnrHihGExHubA-m30a21LBQlomovYZiXJ7mlvUnzFxxa7XOsbA1sFU");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterE).Should().Be("AQAB");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterD).Should().Be("BAOo6qrqQXlCPydfc621qixhn8mnE9VQQoGmoQNsTjMEdcs8lKxe5U2tazIzDAf1j-lbRuRaJIhfJFLhAXZ6YFW4Ix0XvoQBun0dSnn2XELgyLYHSoXlaj53kLYtYHpYTz_7-zzfFfUTvYBBV6YwRJixI7RH95AtWh_b3KJr6oOdmGzul7XcHJ0rcPAKfRXhUrDpjS-iZ3TOAEImQHBwHCjsiQPSDlz3jlUlG-LnE9l3PH49rKFjwc6RIfhKt0jBuwnxE3cX87ux-cFBdo_lIyv2yH-watb9SO1WqxQA2rXBXrWWKitLMhaQLFdHIZEf1lHN7VA_UD9ty9p8CZC21NU");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterP).Should().Be("D0X1M5HmLBNMSvxA_uF-KQ2YnhDmt4ldHiKLjjpJnvJLwXf-TDbApIfHnkRnHxd9adLO4IaAlqL3_oVlS1ZuEijy6auzfwbrcgfsuEYR_k7fG4T8K9TDS2FWe24xFkJgVdRpuMiAt0wZZEexCv2oIFDM0idXrUl7Ikq6RL3kOwob");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterQ).Should().Be("DsKeLZl2Du2RBszDDWKMYhORGR93-CPhSGZT91-Dic6iSWtumfIGAbkjEFiCeMs4tJwktgiYS76IsQ9qCZdrcBj2h-LgMUqrdqKmSq2-krsQPpJxfPadHewa8T2_e48wXzxmx8Dmmoqd4q1LPbOHFMJpY2HBwXopeIbtFa1vUdZP");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterDP).Should().Be("DDNG5nXyVlzoAbI1PSTlQWfx9LntgskAkDTqI6fd7VEBQL9YbIsEIamwxHVBpq196g2SYfovN6Vg0ni-bIrTDECXoh8dGChv5Tv9VUnrz6gzQmldgqnHgyxzB9AC-BP3njg6Z3gKkeEBG4DFJNFw_rdslacFu4_KA5-L4aOKb7rn");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterDQ).Should().Be("Dmzw0Rohwvc1_VJT85n0H8qFzerugkr2255-w87KrP2RqHXh830Rl8-MUGZgpZPgSMwuKOZ_ic-eooWxGcyuSTFsiGQYvrP-ngTaxzPFhHxkpPLVDc-swNjHgCzcHvNT0FAlF2cVOcbuBeNeHOB_za8v9txM1D4Dl_MudTg7Ct2L");
            jwk.KeyParameters.GetValueOrDefault(RSAKeyParameterQI).Should().Be("Aw3In2d6QWQ95rRJwAVAXuWJKubLqSxXTPVu7ueyn1PGMyzK7-6nFNfa1WBpCE4LQ-Ep3eZ2GhSZzN888iixnkNNuaXToUzk0dBEyNM7WDg8tGuyvd5yaJd6wj8q6prYUJGxk7V0mDMhSsA6uttRYe9rbemye6eUNwQIvfmjkbQl");
        }

        [Fact]
        public void JWKWithMinimalRequiredElementsCanBeCreated()
        {
            KeyType keyType = KeyType.EllipticCurve;
            var keyParameters = new Dictionary<KeyParameter, string>
            {
                {ECKeyParameterCRV, "curveName"},
                {ECKeyParameterX, "publicKeyX"},
                {ECKeyParameterY, "publicKeyY"},
                {ECKeyParameterD, "privateKeyD"}
            };

            JWK jwk = new JWK(keyType, keyParameters);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.GetValue("kty").ToString().Should().Be(KeyType.EllipticCurve.Type);
            parsedJWK.GetValue("crv").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterCRV));
            parsedJWK.GetValue("x").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterX));
            parsedJWK.GetValue("y").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterY));
            parsedJWK.GetValue("d").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterD));
        }

        [Fact]
        public void JWKWithECKeyRoundTrip()
        {
            KeyType keyType = KeyType.EllipticCurve;
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES256;
            var keyParameters = new Dictionary<KeyParameter, string>
            {
                {ECKeyParameterCRV, "curveName"},
                {ECKeyParameterX, "publicKeyX"},
                {ECKeyParameterY, "publicKeyY"},
                {ECKeyParameterD, "privateKeyD"}
            };
            JWK jwk = new JWK(keyType, keyParameters, keyUse, keyOperations, algorithm, "test");

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.GetValue("crv").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterCRV));
            parsedJWK.GetValue("x").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterX));
            parsedJWK.GetValue("y").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterY));
            parsedJWK.GetValue("d").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterD));
            parsedJWK.GetValue("kid").ToString().Should().Be("test");

            jwk = new JWK(jwkString);
            jwk.KeyType.Should().Be(keyType);
            jwk.PublicKeyUse.Should().Be(keyUse);
            jwk.KeyOperations.Should().BeEquivalentTo(keyOperations);
            jwk.Algorithm.Should().Be(algorithm);
            jwk.KeyParameters.Should().BeEquivalentTo(keyParameters);
        }


        [Fact]
        public void JWKWithRSAKeyRoundTrip()
        {
            KeyType keyType = KeyType.RSA;
            PublicKeyUse keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            Algorithm algorithm = Algorithm.ES256;
            var keyParameters = new Dictionary<KeyParameter, string>
                {
                    {RSAKeyParameterN, "modulus"},
                    {RSAKeyParameterE, "exponent"},
                    {RSAKeyParameterD, "privateExponent"},
                    {RSAKeyParameterP, "firstPrimeFactor"},
                    {RSAKeyParameterQ, "secondPrimeFactor"},
                    {RSAKeyParameterDP, "firstFactorCRTExponent"},
                    {RSAKeyParameterDQ, "secondFactorCRTExponent"},
                    {RSAKeyParameterQI, "firstCRTCoefficient"}
                };
            JWK jwk = new JWK(keyType, keyParameters, keyUse, keyOperations, algorithm, "test");

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.GetValue("n").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterN));
            parsedJWK.GetValue("e").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterE));
            parsedJWK.GetValue("d").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterD));
            parsedJWK.GetValue("p").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterP));
            parsedJWK.GetValue("q").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterQ));
            parsedJWK.GetValue("dp").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterDP));
            parsedJWK.GetValue("dq").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterDQ));
            parsedJWK.GetValue("qi").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterQI));
            parsedJWK.GetValue("kid").ToString().Should().Be("test");

            jwk = new JWK(jwkString);
            jwk.KeyType.Should().Be(keyType);
            jwk.PublicKeyUse.Should().Be(keyUse);
            jwk.KeyOperations.Should().BeEquivalentTo(keyOperations);
            jwk.Algorithm.Should().Be(algorithm);
            jwk.KeyParameters.Should().BeEquivalentTo(keyParameters);
        }

        [Fact]
        public void JWKCanDeserializationFailNoKeyType()
        {
            // Valid JWK except that key type is missing
            Assert.Throws<ArgumentNullException>(() => new JWK("{\"use\":\"sig\",\"key_ops\":[\"sign\",\"verify\"],\"alg\":\"RS256\",\"kid\":\"e9515a90-7479-4ff8-a3b1-23aaef3b5675\",\"n\":\"4W_ciNjvogFBPf9BYd9jySsrsN6gdosZMAWDi79bZIpYXPHSynbNQUcDe2tSwGKgG9d1ak-jLtZ37SOcC0s1C6W5jAGBHuA-2Oscpa1DZPXrShrDW0wbO2wbBW17pY9rLlnFel-26eE48U0utDdDFCxBBOsWj382sDJzfqLj6DTKBn9r1wDvbRLbWecvZF5uTG392KoO5sNvwwnAhRzo1HX7hPTr5zDOBkfKQolIo99g5Gq9k-_yqDWmRC0mxO6SOfFdrxSMTgCUTyZA_jQXvn7OrSO28yvKdpnrHihGExHubA-m30a21LBQlomovYZiXJ7mlvUnzFxxa7XOsbA1sFU\",\"e\":\"AQAB\",\"d\":\"BAOo6qrqQXlCPydfc621qixhn8mnE9VQQoGmoQNsTjMEdcs8lKxe5U2tazIzDAf1j-lbRuRaJIhfJFLhAXZ6YFW4Ix0XvoQBun0dSnn2XELgyLYHSoXlaj53kLYtYHpYTz_7-zzfFfUTvYBBV6YwRJixI7RH95AtWh_b3KJr6oOdmGzul7XcHJ0rcPAKfRXhUrDpjS-iZ3TOAEImQHBwHCjsiQPSDlz3jlUlG-LnE9l3PH49rKFjwc6RIfhKt0jBuwnxE3cX87ux-cFBdo_lIyv2yH-watb9SO1WqxQA2rXBXrWWKitLMhaQLFdHIZEf1lHN7VA_UD9ty9p8CZC21NU\",\"p\":\"D0X1M5HmLBNMSvxA_uF-KQ2YnhDmt4ldHiKLjjpJnvJLwXf-TDbApIfHnkRnHxd9adLO4IaAlqL3_oVlS1ZuEijy6auzfwbrcgfsuEYR_k7fG4T8K9TDS2FWe24xFkJgVdRpuMiAt0wZZEexCv2oIFDM0idXrUl7Ikq6RL3kOwob\",\"q\":\"DsKeLZl2Du2RBszDDWKMYhORGR93-CPhSGZT91-Dic6iSWtumfIGAbkjEFiCeMs4tJwktgiYS76IsQ9qCZdrcBj2h-LgMUqrdqKmSq2-krsQPpJxfPadHewa8T2_e48wXzxmx8Dmmoqd4q1LPbOHFMJpY2HBwXopeIbtFa1vUdZP\",\"dp\":\"DDNG5nXyVlzoAbI1PSTlQWfx9LntgskAkDTqI6fd7VEBQL9YbIsEIamwxHVBpq196g2SYfovN6Vg0ni-bIrTDECXoh8dGChv5Tv9VUnrz6gzQmldgqnHgyxzB9AC-BP3njg6Z3gKkeEBG4DFJNFw_rdslacFu4_KA5-L4aOKb7rn\",\"dq\":\"Dmzw0Rohwvc1_VJT85n0H8qFzerugkr2255-w87KrP2RqHXh830Rl8-MUGZgpZPgSMwuKOZ_ic-eooWxGcyuSTFsiGQYvrP-ngTaxzPFhHxkpPLVDc-swNjHgCzcHvNT0FAlF2cVOcbuBeNeHOB_za8v9txM1D4Dl_MudTg7Ct2L\",\"qi\":\"Aw3In2d6QWQ95rRJwAVAXuWJKubLqSxXTPVu7ueyn1PGMyzK7-6nFNfa1WBpCE4LQ-Ep3eZ2GhSZzN888iixnkNNuaXToUzk0dBEyNM7WDg8tGuyvd5yaJd6wj8q6prYUJGxk7V0mDMhSsA6uttRYe9rbemye6eUNwQIvfmjkbQl\"}"));
        }

        [Fact]
        public async Task JWKCanBeSerializedInParallel()
        {
            void export()
            {
                KeyType keyType = KeyType.RSA;
                PublicKeyUse keyUse = PublicKeyUse.Signature;
                var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
                Algorithm algorithm = Algorithm.ES256;
                var keyParameters = new Dictionary<KeyParameter, string>
                {
                    {RSAKeyParameterN, "modulus"},
                    {RSAKeyParameterE, "exponent"},
                    {RSAKeyParameterD, "privateExponent"},
                    {RSAKeyParameterP, "firstPrimeFactor"},
                    {RSAKeyParameterQ, "secondPrimeFactor"},
                    {RSAKeyParameterDP, "firstFactorCRTExponent"},
                    {RSAKeyParameterDQ, "secondFactorCRTExponent"},
                    {RSAKeyParameterQI, "firstCRTCoefficient"}
                };
                JWK jwk = new JWK(keyType, keyParameters, keyUse, keyOperations, algorithm, "test");

                var _ = jwk.Export(true);
            }
            
            var tasks = Enumerable.Range(0, 4).Select(_ => Task.Run(export));
            await Task.WhenAll(tasks);
        }
        
        [Fact]
        public void JWKWithRSA256AndIncreasedKeyLengthSignatureCanBeSerialized()
        {
            var keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            var algorithm = Algorithm.RS256;
            var keySize = 3000;
            var jwk = new JWK(algorithm, keyUse, keyOperations, keySize);

            string jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);

            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("n", out var modulus).Should().BeTrue();
            parsedJWK.TryGetValue("e", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("d", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("p", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("q", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dq", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("dp", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("qi", out var _).Should().BeTrue();

            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS256.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation });

            var urlDecodedModulus = Base64Helper.Base64urlDecode(modulus.ToString());
            Assert.Equal(keySize / 8, urlDecodedModulus.Length); // The key length is customarily the number of bits in the public modulus
        }
        
        [Fact]
        public void JWKWithRSA256AndTooLargeKeyLengthThrowsException()
        {
            var keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            var algorithm = Algorithm.RS256;
            var keySize = 20000;

            Assert.Throws<CryptographicException>(() => new JWK(algorithm, keyUse, keyOperations, keySize));
        }

        [Fact]
        public void JWKWithRSA256CanBeCreatedFromRsaKeyAndX509Certificate2()
        {
            using var rsa2048Key = RSA.Create();
            rsa2048Key.KeySize = 2048;
            
            var subject = new X500DistinguishedName("CN=TestCertificate");
            var certificateRequest = new CertificateRequest(
                subject,
                rsa2048Key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            );
            certificateRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature,
                    critical: true
                )
            );
            var notBefore = DateTimeOffset.UtcNow;
            var notAfter = notBefore.AddDays(1);
            X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(notBefore, notAfter);
            
            // KeyType
            KeyType keyType = null;
            switch (rsa2048Key)
            {
                case RSA:
                    keyType = KeyType.RSA;
                    break;
                default:
                    Assert.Fail($"Unknown public key algorithm: '{rsa2048Key.GetType().Name}'");
                    break;
            }
            
            // PublicKeyUse & KeyOperations, can't be extracted from the cert and need to be selected manually 
            var keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
            
            // Algorithm
            var x509PublicKeySignatureAlgorithm = x509Certificate.SignatureAlgorithm.FriendlyName;
            Algorithm algorithm = null;
            switch (x509PublicKeySignatureAlgorithm)
            {
                case "sha256RSA":
                    algorithm = Algorithm.RS256;
                    break;
                case "sha384RSA":
                    algorithm = Algorithm.RS384;
                    break;
                case "sha512RSA":
                    algorithm = Algorithm.RS512;
                    break;
                default:
                    Assert.Fail($"Unknown public key signature algorithm: '{x509PublicKeySignatureAlgorithm}'");
                    break;
            }
            
            var x509PublicKey = x509Certificate.GetPublicKey();
            string keyId = null;
            using (var sha1 = SHA1.Create())
            {
                byte[] ski = sha1.ComputeHash(x509PublicKey);
                keyId = BitConverter.ToString(ski).Replace("-", ":");
            }

            var keyTypeIndication = algorithm.Name.FirstOrDefault();
            Dictionary<KeyParameter, string> keyParameters = null;
            switch (keyTypeIndication)
            {
                case 'R':
                    var rsaKey2048Parameters = rsa2048Key.ExportParameters(true);
                    
                    var modulus = Base64urlEncode(rsaKey2048Parameters.Modulus);
                    var exponent = Base64urlEncode(rsaKey2048Parameters.Exponent);
                    var privateExponent = Base64urlEncode(rsaKey2048Parameters.D);
                    var firstPrimeFactor = Base64urlEncode(rsaKey2048Parameters.P);
                    var secondPrimeFactor = Base64urlEncode(rsaKey2048Parameters.Q);
                    var firstFactorCRTExponent = Base64urlEncode(rsaKey2048Parameters.DP);
                    var secondFactorCRTExponent = Base64urlEncode(rsaKey2048Parameters.DQ);
                    var firstCRTCoefficient = Base64urlEncode(rsaKey2048Parameters.InverseQ);
                    
                    keyParameters = new Dictionary<KeyParameter, string>
                    {
                        {RSAKeyParameterN, modulus},
                        {RSAKeyParameterE, exponent},
                        {RSAKeyParameterD, privateExponent},
                        {RSAKeyParameterP, firstPrimeFactor},
                        {RSAKeyParameterQ, secondPrimeFactor},
                        {RSAKeyParameterDP, firstFactorCRTExponent},
                        {RSAKeyParameterDQ, secondFactorCRTExponent},
                        {RSAKeyParameterQI, firstCRTCoefficient}
                    };
                    break;
            }

            var jwk = new JWK(keyType, keyParameters, keyUse, keyOperations, algorithm, keyId);
            
            var jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);
            
            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.GetValue("n").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterN));
            parsedJWK.GetValue("e").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterE));
            parsedJWK.GetValue("d").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterD));
            parsedJWK.GetValue("p").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterP));
            parsedJWK.GetValue("q").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterQ));
            parsedJWK.GetValue("dp").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterDP));
            parsedJWK.GetValue("dq").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterDQ));
            parsedJWK.GetValue("qi").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterQI));
            
            parsedJWK.GetValue("kty").ToString().Should().Be("RSA");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.RS256.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation });
        }
        
        [Fact]
        public void JWKWithES256CanBeCreatedFromEcKeyAndX509Certificate2()
        {
            // Create key and cert
            using var ecP256Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            
            var subject = new X500DistinguishedName("CN=TestCertificate");
            var certificateRequest = new CertificateRequest(
                subject,
                ecP256Key,
                HashAlgorithmName.SHA256
            );
            certificateRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature,
                    critical: true
                )
            );
            var notBefore = DateTimeOffset.UtcNow;
            var notAfter = notBefore.AddDays(1);
            X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(notBefore, notAfter);
            
            // PublicKeyUse & KeyOperations, can't be extracted from the cert and need to be selected manually 
            var keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
            
            // KeyType
            KeyType keyType = null;
            switch (ecP256Key)
            {
                case ECDsa:
                    keyType = KeyType.EllipticCurve;
                    break;
                default:
                    Assert.Fail($"Unknown public key algorithm: '{ecP256Key.GetType().Name}'");
                    break;
            }
            
            // Algorithm
            var x509PublicKeySignatureAlgorithm = x509Certificate.SignatureAlgorithm.FriendlyName;
            Algorithm algorithm = null;
            switch (x509PublicKeySignatureAlgorithm)
            {
                case "sha256ECDSA":
                    algorithm = Algorithm.ES256;
                    break;
                case "sha384ECDSA":
                    algorithm = Algorithm.ES384;
                    break;
                case "sha512ECDSA":
                    algorithm = Algorithm.ES512;
                    break;
                default:
                    Assert.Fail($"Unknown public key signature algorithm: '{x509PublicKeySignatureAlgorithm}'");
                    break;
            }
            
            var x509PublicKey = x509Certificate.GetPublicKey();
            string keyId = null;
            using (var sha1 = SHA1.Create())
            {
                byte[] ski = sha1.ComputeHash(x509PublicKey);
                keyId = BitConverter.ToString(ski).Replace("-", ":");
            }

            var keyTypeIndication = algorithm.Name.FirstOrDefault();
            Dictionary<KeyParameter, string> keyParameters = null;
            switch (keyTypeIndication)
            {
                case 'E':
                    var ecP26KeyParameters = ecP256Key.ExportParameters(true);
                    
                    var privateKeyD = Base64urlEncode(ecP26KeyParameters.D);
                    var publicKeyX = Base64urlEncode(ecP26KeyParameters.Q.X);
                    var publicKeyY = Base64urlEncode(ecP26KeyParameters.Q.Y);
                    
                    var keyLength = algorithm.Name.Split(new string[] { "ES" }, StringSplitOptions.None)[1]; // Algorithm = 'ES' + Keylength
                    var curveName = "P-" + keyLength;
                    
                    keyParameters = new Dictionary<KeyParameter, string>
                    {
                        {ECKeyParameterCRV, curveName},
                        {ECKeyParameterX, publicKeyX},
                        {ECKeyParameterY, publicKeyY},
                        {ECKeyParameterD, privateKeyD}
                    };
                    
                    break;
            }

            var jwk = new JWK(keyType, keyParameters, keyUse, keyOperations, algorithm, keyId);
            
            var jwkString = jwk.Export(true);
            var parsedJWK = JObject.Parse(jwkString);
            
            parsedJWK.TryGetValue("kty", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("alg", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("use", out var _).Should().BeTrue();
            parsedJWK.TryGetValue("kid", out var _).Should().BeTrue();
            parsedJWK.GetValue("crv").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterCRV));
            parsedJWK.GetValue("x").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterX));
            parsedJWK.GetValue("y").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterY));
            parsedJWK.GetValue("d").ToString().Should().Be(keyParameters.GetValueOrDefault(ECKeyParameterD));
            
            parsedJWK.GetValue("kty").ToString().Should().Be("EC");
            parsedJWK.GetValue("alg").ToString().Should().Be(Algorithm.ES256.Name);
            parsedJWK.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
            parsedJWK.GetValue("key_ops").Values<string>().Count().Should().Be(2);
            parsedJWK.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] { KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation });
        }
    }
}
