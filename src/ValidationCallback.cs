#region License
/*
Copyright (c) 2018 Konrad Mattheis und Martin Berthold
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#endregion

namespace Q2g.HelperQlik
{
    #region Usings
    using NLog;
    using Ser.Api;
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Http;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Linq;
    #endregion

    public static class ValidationCallback
    {
        #region Logger
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        #endregion

        #region Properties
        public static SerConnection Connection { get; set; }
        #endregion

        #region Public Methods
        public static bool ValidateRemoteCertificate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors error)
        {
            try
            {
                if (error == SslPolicyErrors.None)
                    return true;

                if (!Connection.SslVerify)
                    return true;

                logger.Debug("Validate Server Certificate...");
                Uri requestUri = null;
                if (sender is HttpRequestMessage hrm)
                    requestUri = hrm.RequestUri;
                if (sender is HttpClient hc)
                    requestUri = hc.BaseAddress;
                if (sender is HttpWebRequest hwr)
                    requestUri = hwr.Address;
                if (sender is Uri wsuri)
                    requestUri = wsuri;

                if (requestUri != null)
                {
                    logger.Debug("Validate Thumbprints...");
                    var thumbprints = Connection?.SslValidThumbprints ?? new List<SerThumbprint>();
                    foreach (var item in thumbprints)
                    {
                        try
                        {
                            Uri uri = null;
                            if (!String.IsNullOrEmpty(item.Url))
                                uri = new Uri(item.Url);
                            var thumbprint = item.Thumbprint.Replace(":", "").Replace(" ", "").ToLowerInvariant();
                            var certThumbprint = cert.GetCertHashString().ToLowerInvariant();
                            if ((thumbprint == certThumbprint)
                                &&
                                ((uri == null) || (uri.Host.ToLowerInvariant() == requestUri.Host.ToLowerInvariant())))
                                return true;
                        }
                        catch (Exception ex)
                        {
                            logger.Error(ex, "Thumbprint could not be validated.");
                        }
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                logger.Error(ex, "The SSL-Validation was faild.");
                return false;
            }
        }
        #endregion
    }
}