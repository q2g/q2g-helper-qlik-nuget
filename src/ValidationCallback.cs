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

        #region Private Methods
        private static string TrimHiddenChars(string value)
        {
            var chars = value.ToCharArray().Where(c => c < 128).ToArray();
            return new string(chars);
        }
        #endregion

        #region Public Methods
        public static bool ValidateRemoteCertificate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors error)
        {
            try
            {
                logger.Debug("The server called ssl certificate validation...");

                if (error == SslPolicyErrors.None)
                {
                    logger.Debug("No SSL policy errors.");
                    return true;
                }

                if (!Connection?.SslVerify ?? false)
                {
                    logger.Info("Use property 'SslVertify' with value 'false'.");
                    return true;
                }

                logger.Debug("Validate server certificate...");
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
                    logger.Debug("Validate thumbprints...");
                    var thumbprints = Connection?.SslValidThumbprints ?? new List<SerThumbprint>();
                    foreach (var item in thumbprints)
                    {
                        try
                        {
                            Uri uri = null;
                            if (!String.IsNullOrEmpty(item.Url))
                                uri = new Uri(item.Url);
                            string thumbprint = TrimHiddenChars(item.Thumbprint.Replace(":", "").Replace(" ", "").ToLowerInvariant());
                            string certThumbprint = TrimHiddenChars(cert.GetCertHashString().ToLowerInvariant());
                            if ((thumbprint == certThumbprint)
                                && ((uri == null) || (uri.Host.ToLowerInvariant() == requestUri.Host.ToLowerInvariant())))
                            {
                                logger.Debug("Thumbprint was successfully found.");
                                return true;
                            }
                        }
                        catch (Exception ex)
                        {
                            logger.Error(ex, "Thumbprint could not be validated.");
                        }
                    }

                    logger.Debug("No correct thumbprint found.");
                }
                return false;
            }
            catch (Exception ex)
            {
                logger.Error(ex, "The SSL validation was faild.");
                return false;
            }
        }
        #endregion
    }
}