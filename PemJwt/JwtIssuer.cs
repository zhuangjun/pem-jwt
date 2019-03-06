using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PemJwt
{
    public class JwtIssuer
    {
        private const String PUBLIC_PEM_HEADER = "-----BEGIN PUBLIC KEY-----";
        private const String PUBLIC_PEM_FOOTER = "-----END PUBLIC KEY-----";
        private const String PRIVATE_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
        private const String PRIVATE_PRM_FOOTER = "-----END RSA PRIVATE KEY-----";

        private static readonly long _ticks_since_1970_1_1 = new DateTime(1970, 1, 1).Ticks;

        private static ConcurrentDictionary<string, RSAParameters> _privateRsaParametersDist = new ConcurrentDictionary<string, RSAParameters>();
        private static ConcurrentDictionary<string, RSAParameters> _publicRsaParametersDist = new ConcurrentDictionary<string, RSAParameters>();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="claims">claims object</param>
        /// <param name="privateKeyId">private key file path</param>
        /// <param name="publicKeyId">public key file path</param>
        /// <returns></returns>
        public static string Encode(Claims claims
            , string privateKeyId
            , IDictionary<string, object> extraHeaders = null)
        {
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }
            if (claims.Payload == null || !claims.Payload.Any())
            {
                throw new ArgumentException("Claims.Payload cannot be null.");
            }

            // Build payload
            var payload = new Dictionary<string, object>();
            foreach (var pair in claims.Payload)
            {
                payload.Add(pair.Key, pair.Value);
            }
            if (claims.ExpireData.HasValue)
            {
                payload.Add(Claims.EXPIRATION, ToUtcSeconds(claims.ExpireData.Value));
                payload.Add(Claims.ISSUED_AT, ToUtcSeconds(DateTime.Now));
            }

            // Generate JWT
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(GetPrivatePemRSAParameters(privateKeyId));
                return Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.RS256, extraHeaders);
            }
        }

        /// <summary>
        /// Decode jwt by public key.
        /// 
        /// </summary>
        /// <param name="jwt">jwt string</param>
        /// <param name="publicKeyId">public key file path</param>
        /// <returns></returns>
        public static Dictionary<string, object> Decode(string jwt, string publicKeyId)
        {
            if (string.IsNullOrEmpty(jwt))
            {
                throw new ArgumentNullException(nameof(jwt));
            }
            if (string.IsNullOrEmpty(publicKeyId))
            {
                throw new ArgumentNullException(nameof(publicKeyId));
            }

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(GetPublicPemRSAParameters(publicKeyId));
                var payload = Jose.JWT.Decode<Dictionary<string, object>>(jwt, rsa);
                if (payload != null)
                {
                    if (payload.ContainsKey(Claims.EXPIRATION))
                    {
                        long expireDateInUtcSeconds;
                        if (!long.TryParse(payload[Claims.EXPIRATION].ToString(), out expireDateInUtcSeconds))
                        {
                            throw new Exception("Invalid exp:" + payload[Claims.EXPIRATION]);
                        }
                        if (HasJwtExpired(expireDateInUtcSeconds))
                        {
                            throw new Exception("Jwt has expired.");
                        }
                    }
                }

                return payload;
            }
        }

        private static RSAParameters GetPrivatePemRSAParameters(string privateKeyId)
        {
            RSAParameters rsaKeyInfo;
            if (!_privateRsaParametersDist.TryGetValue(privateKeyId, out rsaKeyInfo))
            {
                if (!File.Exists(privateKeyId))
                {
                    throw new ArgumentException("Invalid private key path:" + privateKeyId);
                }

                var pemContent = File.ReadAllText(privateKeyId).Trim();
                if (!IsPrivateKey(pemContent))
                {
                    throw new ArgumentException("Invalid private pem format:" + privateKeyId);
                }

                using (var txtreader = new StringReader(pemContent))
                {
                    var keyPair = (AsymmetricCipherKeyPair)new PemReader(txtreader).ReadObject();
                    rsaKeyInfo = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);

                    _privateRsaParametersDist.TryAdd(privateKeyId, rsaKeyInfo);
                }
            }

            return rsaKeyInfo;
        }

        private static RSAParameters GetPublicPemRSAParameters(string publicKeyId)
        {
            RSAParameters rsaKeyInfo;
            if (!_publicRsaParametersDist.TryGetValue(publicKeyId, out rsaKeyInfo))
            {
                if (!File.Exists(publicKeyId))
                {
                    throw new ArgumentException("Invalid public key path:" + publicKeyId);
                }

                var pemContent = File.ReadAllText(publicKeyId);
                if (!IsPublicKey(pemContent))
                {
                    throw new ArgumentException("Invalid public pem format:" + publicKeyId);
                }

                using (var txtreader = new StringReader(pemContent))
                {
                    var keyPair = (RsaKeyParameters)new PemReader(txtreader).ReadObject();
                    rsaKeyInfo = DotNetUtilities.ToRSAParameters(keyPair);

                    _publicRsaParametersDist.TryAdd(publicKeyId, rsaKeyInfo);
                }
            }

            return rsaKeyInfo;
        }

        private static bool IsPrivateKey(string pemContent)
        {
            return pemContent.StartsWith(PRIVATE_PEM_HEADER) && pemContent.EndsWith(PRIVATE_PRM_FOOTER);
        }

        private static bool IsPublicKey(string pemContent)
        {
            return pemContent.StartsWith(PUBLIC_PEM_HEADER) && pemContent.EndsWith(PUBLIC_PEM_FOOTER);
        }

        private static long ToUtcSeconds(DateTime dt)
        {
            return (dt.ToUniversalTime().Ticks - _ticks_since_1970_1_1) / TimeSpan.TicksPerSecond;
        }

        private static bool HasJwtExpired(long expireDateInUtcSeconds)
        {
            var expireDateTicks = expireDateInUtcSeconds * TimeSpan.TicksPerSecond + _ticks_since_1970_1_1;
            return DateTime.Now.ToUniversalTime().Ticks > expireDateTicks;
        }
    }
}
