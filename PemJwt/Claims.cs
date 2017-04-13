using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PemJwt
{
    public class Claims
    {
        /** JWT claims parameter name: <code>"iss"</code> */
        public const string ISSUER = "iss";

        /** JWT claims parameter name: <code>"sub"</code> */
        public const string SUBJECT = "sub";

        /** JWT claims parameter name: <code>"aud"</code> */
        public const string AUDIENCE = "aud";

        /** JWT claims parameter name: <code>"exp"</code> */
        public const string EXPIRATION = "exp";

        /** JWT claims parameter name: <code>"nbf"</code> */
        public const string NOT_BEFORE = "nbf";

        /** JWT claims parameter name: <code>"iat"</code> */
        public const string ISSUED_AT = "iat";

        /** JWT claims parameter name: <code>"jti"</code> */
        public const string ID = "jti";

        public DateTime? ExpireData { get; set; }

        public IDictionary<string, object> Payload { get; set; }

    }
}
