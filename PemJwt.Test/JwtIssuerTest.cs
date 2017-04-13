using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;

namespace PemJwt.Test
{
    [TestClass]
    public class JwtIssuerTest
    {
        [TestMethod]
        public void Encode()
        {
            var privateKeyId = "keys/private/test.pem";
            var claims = new Claims()
            {
                ExpireData = DateTime.Now.AddMinutes(1),
                Payload = new Dictionary<string, object>()
                {
                    {"hello","world" }
                }
            };

            var jwt = JwtIssuer.Encode(claims, privateKeyId);
            Assert.IsNotNull(jwt);
        }

        [TestMethod]
        public void DecodeTest_ExpireNotSet()
        {
            var privateKeyId = "keys/private/test.pem";
            var publicKeyId = "keys/public/test.pem";
            var claims = new Claims()
            {
                Payload = new Dictionary<string, object>()
                {
                    {"hello","world" }
                }
            };

            var jwt = JwtIssuer.Encode(claims, privateKeyId);
            Assert.IsNotNull(jwt);

            var payload = JwtIssuer.Decode(jwt, publicKeyId);
            Assert.AreEqual("world", payload["hello"]);
        }

        [TestMethod]
        public void DecodeTest_HasNotExpired()
        {
            var privateKeyId = "keys/private/test.pem";
            var publicKeyId = "keys/public/test.pem";
            var claims = new Claims()
            {
                ExpireData = DateTime.Now.AddMinutes(1),
                Payload = new Dictionary<string, object>()
                {
                    {"hello","world" }
                }
            };

            var jwt = JwtIssuer.Encode(claims, privateKeyId);
            Assert.IsNotNull(jwt);

            var payload = JwtIssuer.Decode(jwt, publicKeyId);
            Assert.AreEqual("world", payload["hello"]);
        }



        [TestMethod]
        [ExpectedException(typeof(Exception))]
        public void DecodeTest_Expire()
        {
            var privateKeyId = "keys/private/test.pem";
            var publicKeyId = "keys/public/test.pem";
            var claims = new Claims()
            {
                ExpireData = DateTime.Now.AddMinutes(-1),
                Payload = new Dictionary<string, object>()
                {
                    {"hello","world" }
                }
            };

            var jwt = JwtIssuer.Encode(claims, privateKeyId);
            Assert.IsNotNull(jwt);

            var payload = JwtIssuer.Decode(jwt, publicKeyId);
        }
    }
}
