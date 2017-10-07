using System.IO;
using Bacs.Problem;
using Google.Protobuf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Bacs.StatementProvider
{
    public class StatementProvider
    {
        private readonly string _baseUrl;
        private readonly string _referrer;
        private readonly string _certPath;

        public StatementProvider(string baseUrl, string referrer, string certPath)
        {
            _baseUrl = baseUrl;
            _referrer = referrer;
            _certPath = certPath;
        }

        public string GetStatementUrl(string package, byte[] hash)
        {
            var request = new Request
            {
                Package = package,
                Revision = Revision.Parser.ParseFrom(hash)
            };
            var requestBytes = request.ToByteArray();
            var base64Request = Base64Url.ToBase64ForUrlString(requestBytes);

            var signatureBytes = Sign(requestBytes);
            var base64Signature = Base64Url.ToBase64ForUrlString(signatureBytes);

            return string.Format("{0}/get/{1}/{2}/{3}", _baseUrl, base64Request, _referrer, base64Signature);
        }
        
        private byte[] Sign(byte[] data)
        {
            var key = ReadKey();
            var sig = SignerUtilities.GetSigner("SHA1withRSA");

            sig.Init(true, key);
            sig.BlockUpdate(data, 0, data.Length);

            return sig.GenerateSignature();
        }
        
        private AsymmetricKeyParameter ReadKey()
        {
            using (var stream = File.OpenText(_certPath))
            {
                var pemReader = new PemReader(stream);
                return (AsymmetricKeyParameter)pemReader.ReadObject();
            }
        }
    }
}