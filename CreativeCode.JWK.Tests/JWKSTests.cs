using System.Collections.Generic;
using System.Linq;
using CreativeCode.JWK.KeyParts;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using Xunit;
using static CreativeCode.JWK.KeyParts.KeyParameter;

namespace CreativeCode.JWK.Tests;

public class JWKSTests
{
    [Fact]
    public void JWKSWithRSAKeyCanBeSerialized()
    {
        var keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[] {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithm = Algorithm.RS256;
        var jwk = new JWK(algorithm, keyUse, keyOperations);
        var jwks = new JWKS(new[] {jwk});

        string jwksString = jwks.Export(true);
        var parsedJWKS = JObject.Parse(jwksString);

        parsedJWKS.TryGetValue("keys", out var keys);
        var rsaKey = keys.Children().FirstOrDefault() as JObject;

        rsaKey.TryGetValue("kty", out var _).Should().BeTrue();
        rsaKey.TryGetValue("alg", out var _).Should().BeTrue();
        rsaKey.TryGetValue("use", out var _).Should().BeTrue();
        rsaKey.TryGetValue("kid", out var _).Should().BeTrue();
        rsaKey.TryGetValue("n", out var _).Should().BeTrue();
        rsaKey.TryGetValue("e", out var _).Should().BeTrue();
        rsaKey.TryGetValue("d", out var _).Should().BeTrue();
        rsaKey.TryGetValue("p", out var _).Should().BeTrue();
        rsaKey.TryGetValue("q", out var _).Should().BeTrue();
        rsaKey.TryGetValue("dq", out var _).Should().BeTrue();
        rsaKey.TryGetValue("dp", out var _).Should().BeTrue();
        rsaKey.TryGetValue("qi", out var _).Should().BeTrue();

        rsaKey.GetValue("kty").ToString().Should().Be("RSA");
        rsaKey.GetValue("alg").ToString().Should().Be(Algorithm.RS256.Name);
        rsaKey.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
        rsaKey.GetValue("key_ops").Values<string>().Count().Should().Be(2);
        rsaKey.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] {KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation});
    }

    [Fact]
    public void JWKSWithMultipleMixedKeysCanBeSerialized()
    {
        // RSA Key
        var keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[]
            {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        var algorithm = Algorithm.RS256;
        var jwkRSA = new JWK(algorithm, keyUse, keyOperations);

        // EC Key
        keyUse = PublicKeyUse.Signature;
        keyOperations = new HashSet<KeyOperation>(new[]
            {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        algorithm = Algorithm.ES256;
        JWK jwkEC = new JWK(algorithm, keyUse, keyOperations);

        var jwks = new JWKS(new[] {jwkRSA, jwkEC});

        string jwksString = jwks.Export(true);
        var parsedJWKS = JObject.Parse(jwksString);

        parsedJWKS.TryGetValue("keys", out var keys);

        var rsaKey = keys.Children().First() as JObject;
        rsaKey.TryGetValue("kty", out var _).Should().BeTrue();
        rsaKey.TryGetValue("alg", out var _).Should().BeTrue();
        rsaKey.TryGetValue("use", out var _).Should().BeTrue();
        rsaKey.TryGetValue("kid", out var _).Should().BeTrue();
        rsaKey.TryGetValue("n", out var _).Should().BeTrue();
        rsaKey.TryGetValue("e", out var _).Should().BeTrue();
        rsaKey.TryGetValue("d", out var _).Should().BeTrue();
        rsaKey.TryGetValue("p", out var _).Should().BeTrue();
        rsaKey.TryGetValue("q", out var _).Should().BeTrue();
        rsaKey.TryGetValue("dq", out var _).Should().BeTrue();
        rsaKey.TryGetValue("dp", out var _).Should().BeTrue();
        rsaKey.TryGetValue("qi", out var _).Should().BeTrue();

        rsaKey.GetValue("kty").ToString().Should().Be("RSA");
        rsaKey.GetValue("alg").ToString().Should().Be(Algorithm.RS256.Name);
        rsaKey.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
        rsaKey.GetValue("key_ops").Values<string>().Count().Should().Be(2);
        rsaKey.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] {KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation});

        var ecKey = keys.Children().Last() as JObject;
        ecKey.TryGetValue("kty", out var _).Should().BeTrue();
        ecKey.TryGetValue("alg", out var _).Should().BeTrue();
        ecKey.TryGetValue("use", out var _).Should().BeTrue();
        ecKey.TryGetValue("kid", out var _).Should().BeTrue();
        ecKey.TryGetValue("crv", out var _).Should().BeTrue();
        ecKey.TryGetValue("x", out var _).Should().BeTrue();
        ecKey.TryGetValue("y", out var _).Should().BeTrue();
        ecKey.TryGetValue("d", out var _).Should().BeTrue();

        ecKey.GetValue("kty").ToString().Should().Be("EC");
        ecKey.GetValue("alg").ToString().Should().Be(Algorithm.ES256.Name);
        ecKey.GetValue("use").ToString().Should().Be(PublicKeyUse.Signature.KeyUse);
        ecKey.GetValue("key_ops").Values<string>().Count().Should().Be(2);
        ecKey.GetValue("key_ops").Values<string>().Should().BeEquivalentTo(new[] {KeyOperation.ComputeDigitalSignature.Operation, KeyOperation.VerifyDigitalSignature.Operation});
    }

    [Fact]
    public void JWKSCanBeDeserialized()
    {
        var jwks = new JWKS("{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"key_ops\":[\"sign\",\"verify\"],\"alg\":\"RS256\",\"kid\":\"e9515a90-7479-4ff8-a3b1-23aaef3b5675\",\"n\":\"4W_ciNjvogFBPf9BYd9jySsrsN6gdosZMAWDi79bZIpYXPHSynbNQUcDe2tSwGKgG9d1ak-jLtZ37SOcC0s1C6W5jAGBHuA-2Oscpa1DZPXrShrDW0wbO2wbBW17pY9rLlnFel-26eE48U0utDdDFCxBBOsWj382sDJzfqLj6DTKBn9r1wDvbRLbWecvZF5uTG392KoO5sNvwwnAhRzo1HX7hPTr5zDOBkfKQolIo99g5Gq9k-_yqDWmRC0mxO6SOfFdrxSMTgCUTyZA_jQXvn7OrSO28yvKdpnrHihGExHubA-m30a21LBQlomovYZiXJ7mlvUnzFxxa7XOsbA1sFU\",\"e\":\"AQAB\",\"d\":\"BAOo6qrqQXlCPydfc621qixhn8mnE9VQQoGmoQNsTjMEdcs8lKxe5U2tazIzDAf1j-lbRuRaJIhfJFLhAXZ6YFW4Ix0XvoQBun0dSnn2XELgyLYHSoXlaj53kLYtYHpYTz_7-zzfFfUTvYBBV6YwRJixI7RH95AtWh_b3KJr6oOdmGzul7XcHJ0rcPAKfRXhUrDpjS-iZ3TOAEImQHBwHCjsiQPSDlz3jlUlG-LnE9l3PH49rKFjwc6RIfhKt0jBuwnxE3cX87ux-cFBdo_lIyv2yH-watb9SO1WqxQA2rXBXrWWKitLMhaQLFdHIZEf1lHN7VA_UD9ty9p8CZC21NU\",\"p\":\"D0X1M5HmLBNMSvxA_uF-KQ2YnhDmt4ldHiKLjjpJnvJLwXf-TDbApIfHnkRnHxd9adLO4IaAlqL3_oVlS1ZuEijy6auzfwbrcgfsuEYR_k7fG4T8K9TDS2FWe24xFkJgVdRpuMiAt0wZZEexCv2oIFDM0idXrUl7Ikq6RL3kOwob\",\"q\":\"DsKeLZl2Du2RBszDDWKMYhORGR93-CPhSGZT91-Dic6iSWtumfIGAbkjEFiCeMs4tJwktgiYS76IsQ9qCZdrcBj2h-LgMUqrdqKmSq2-krsQPpJxfPadHewa8T2_e48wXzxmx8Dmmoqd4q1LPbOHFMJpY2HBwXopeIbtFa1vUdZP\",\"dp\":\"DDNG5nXyVlzoAbI1PSTlQWfx9LntgskAkDTqI6fd7VEBQL9YbIsEIamwxHVBpq196g2SYfovN6Vg0ni-bIrTDECXoh8dGChv5Tv9VUnrz6gzQmldgqnHgyxzB9AC-BP3njg6Z3gKkeEBG4DFJNFw_rdslacFu4_KA5-L4aOKb7rn\",\"dq\":\"Dmzw0Rohwvc1_VJT85n0H8qFzerugkr2255-w87KrP2RqHXh830Rl8-MUGZgpZPgSMwuKOZ_ic-eooWxGcyuSTFsiGQYvrP-ngTaxzPFhHxkpPLVDc-swNjHgCzcHvNT0FAlF2cVOcbuBeNeHOB_za8v9txM1D4Dl_MudTg7Ct2L\",\"qi\":\"Aw3In2d6QWQ95rRJwAVAXuWJKubLqSxXTPVu7ueyn1PGMyzK7-6nFNfa1WBpCE4LQ-Ep3eZ2GhSZzN888iixnkNNuaXToUzk0dBEyNM7WDg8tGuyvd5yaJd6wj8q6prYUJGxk7V0mDMhSsA6uttRYe9rbemye6eUNwQIvfmjkbQl\"}]}");
        jwks.Keys.First().KeyType.Should().Be(KeyType.RSA);
        jwks.Keys.First().PublicKeyUse.Should().Be(PublicKeyUse.Signature);
        jwks.Keys.First().KeyOperations.Should().BeEquivalentTo(new HashSet<KeyOperation>()
            {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
        jwks.Keys.First().Algorithm.Should().Be(Algorithm.RS256);
        jwks.Keys.First().KeyID.Should().Be("e9515a90-7479-4ff8-a3b1-23aaef3b5675");
        jwks.Keys.First().KeyParameters.GetValueOrDefault(RSAKeyParameterN).Should().Be(
            "4W_ciNjvogFBPf9BYd9jySsrsN6gdosZMAWDi79bZIpYXPHSynbNQUcDe2tSwGKgG9d1ak-jLtZ37SOcC0s1C6W5jAGBHuA-2Oscpa1DZPXrShrDW0wbO2wbBW17pY9rLlnFel-26eE48U0utDdDFCxBBOsWj382sDJzfqLj6DTKBn9r1wDvbRLbWecvZF5uTG392KoO5sNvwwnAhRzo1HX7hPTr5zDOBkfKQolIo99g5Gq9k-_yqDWmRC0mxO6SOfFdrxSMTgCUTyZA_jQXvn7OrSO28yvKdpnrHihGExHubA-m30a21LBQlomovYZiXJ7mlvUnzFxxa7XOsbA1sFU");
        jwks.Keys.First().KeyParameters.GetValueOrDefault(RSAKeyParameterE).Should().Be("AQAB");
        jwks.Keys.First().KeyParameters.GetValueOrDefault(RSAKeyParameterD).Should().Be(
            "BAOo6qrqQXlCPydfc621qixhn8mnE9VQQoGmoQNsTjMEdcs8lKxe5U2tazIzDAf1j-lbRuRaJIhfJFLhAXZ6YFW4Ix0XvoQBun0dSnn2XELgyLYHSoXlaj53kLYtYHpYTz_7-zzfFfUTvYBBV6YwRJixI7RH95AtWh_b3KJr6oOdmGzul7XcHJ0rcPAKfRXhUrDpjS-iZ3TOAEImQHBwHCjsiQPSDlz3jlUlG-LnE9l3PH49rKFjwc6RIfhKt0jBuwnxE3cX87ux-cFBdo_lIyv2yH-watb9SO1WqxQA2rXBXrWWKitLMhaQLFdHIZEf1lHN7VA_UD9ty9p8CZC21NU");
        jwks.Keys.First().KeyParameters.GetValueOrDefault(RSAKeyParameterP).Should().Be(
            "D0X1M5HmLBNMSvxA_uF-KQ2YnhDmt4ldHiKLjjpJnvJLwXf-TDbApIfHnkRnHxd9adLO4IaAlqL3_oVlS1ZuEijy6auzfwbrcgfsuEYR_k7fG4T8K9TDS2FWe24xFkJgVdRpuMiAt0wZZEexCv2oIFDM0idXrUl7Ikq6RL3kOwob");
        jwks.Keys.First().KeyParameters.GetValueOrDefault(RSAKeyParameterQ).Should().Be(
            "DsKeLZl2Du2RBszDDWKMYhORGR93-CPhSGZT91-Dic6iSWtumfIGAbkjEFiCeMs4tJwktgiYS76IsQ9qCZdrcBj2h-LgMUqrdqKmSq2-krsQPpJxfPadHewa8T2_e48wXzxmx8Dmmoqd4q1LPbOHFMJpY2HBwXopeIbtFa1vUdZP");
        jwks.Keys.First().KeyParameters.GetValueOrDefault(RSAKeyParameterDP).Should().Be(
            "DDNG5nXyVlzoAbI1PSTlQWfx9LntgskAkDTqI6fd7VEBQL9YbIsEIamwxHVBpq196g2SYfovN6Vg0ni-bIrTDECXoh8dGChv5Tv9VUnrz6gzQmldgqnHgyxzB9AC-BP3njg6Z3gKkeEBG4DFJNFw_rdslacFu4_KA5-L4aOKb7rn");
        jwks.Keys.First().KeyParameters.GetValueOrDefault(RSAKeyParameterDQ).Should().Be(
            "Dmzw0Rohwvc1_VJT85n0H8qFzerugkr2255-w87KrP2RqHXh830Rl8-MUGZgpZPgSMwuKOZ_ic-eooWxGcyuSTFsiGQYvrP-ngTaxzPFhHxkpPLVDc-swNjHgCzcHvNT0FAlF2cVOcbuBeNeHOB_za8v9txM1D4Dl_MudTg7Ct2L");
        jwks.Keys.First().KeyParameters.GetValueOrDefault(RSAKeyParameterQI).Should().Be(
            "Aw3In2d6QWQ95rRJwAVAXuWJKubLqSxXTPVu7ueyn1PGMyzK7-6nFNfa1WBpCE4LQ-Ep3eZ2GhSZzN888iixnkNNuaXToUzk0dBEyNM7WDg8tGuyvd5yaJd6wj8q6prYUJGxk7V0mDMhSsA6uttRYe9rbemye6eUNwQIvfmjkbQl");
    }

    [Fact]
    public void JWKSWithRSAKeyRoundTrip()
    {
        KeyType keyType = KeyType.RSA;
        PublicKeyUse keyUse = PublicKeyUse.Signature;
        var keyOperations = new HashSet<KeyOperation>(new[]
            {KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature});
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
        JWKS jwks = new JWKS(new[] {jwk});
        
        string jwksString = jwks.Export(true);
        var parsedJWKS = JObject.Parse(jwksString);
        var parsedJWK = parsedJWKS.GetValue("keys").First as JObject;

        parsedJWK.GetValue("n").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterN));
        parsedJWK.GetValue("e").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterE));
        parsedJWK.GetValue("d").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterD));
        parsedJWK.GetValue("p").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterP));
        parsedJWK.GetValue("q").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterQ));
        parsedJWK.GetValue("dp").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterDP));
        parsedJWK.GetValue("dq").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterDQ));
        parsedJWK.GetValue("qi").ToString().Should().Be(keyParameters.GetValueOrDefault(RSAKeyParameterQI));
        parsedJWK.GetValue("kid").ToString().Should().Be("test");

        jwks = new JWKS(jwksString);
        jwks.Keys.First().KeyType.Should().Be(keyType);
        jwks.Keys.First().PublicKeyUse.Should().Be(keyUse);
        jwks.Keys.First().KeyOperations.Should().BeEquivalentTo(keyOperations);
        jwks.Keys.First().Algorithm.Should().Be(algorithm);
        jwks.Keys.First().KeyParameters.Should().BeEquivalentTo(keyParameters);
    }
}