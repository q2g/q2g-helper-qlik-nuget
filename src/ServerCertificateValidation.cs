namespace Q2g.HelperQlik
{
    #region Usings
    using NLog;
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Http;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    using System.Linq;
    using Ser.Api.Model;
    #endregion

    public static class ServerCertificateValidation
    {
        #region Logger
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        #endregion

        #region Properties
        public static SerConnection Connection { get; set; }
        public static List<Uri> AlternativeUris { get; private set; }
        #endregion

        #region Private Methods
        private static string TrimHiddenChars(string value)
        {
            var chars = value.ToCharArray().Where(c => c < 128).ToArray();
            return new string(chars);
        }
        #endregion

        #region Public Methods
        public static bool Validate(object sender, X509Certificate2 cert, SslPolicyErrors error)
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

        public static void ReadAlternativeDnsNames(Uri serverUri, X509Certificate2 cert)
        {
            try
            {
                if (AlternativeUris != null)
                    return;

                AlternativeUris = new List<Uri>();
                var dnsNames = new List<string>();
                var cnName = cert.Subject?.Split(',')?.FirstOrDefault()?.Replace("CN=", "");
                if (cnName != null)
                    dnsNames.Add(cnName);
                var bytehosts = cert?.Extensions["2.5.29.17"] ?? null;
                if (bytehosts != null)
                {
                    var names = bytehosts.Format(false)?.Split(',', StringSplitOptions.RemoveEmptyEntries);
                    foreach (var name in names)
                        dnsNames.Add(name.Replace("DNS-Name=", "").Trim());
                }

                foreach (var dnsName in dnsNames)
                {
                    var uriBuilder = new UriBuilder(serverUri)
                    {
                        Host = dnsName
                    };
                    AlternativeUris.Add(uriBuilder.Uri);
                }
                AlternativeUris = AlternativeUris?.Distinct()?.ToList() ?? new List<Uri>();
            }
            catch (Exception ex)
            {
                logger.Error(ex, "The alternative dns names could´t not read.");
            }
        }
        #endregion
    }
}