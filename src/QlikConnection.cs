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
    using System;
    using System.Linq;
    using System.Net;
    using NLog;
    using System.Security.Cryptography.X509Certificates;
    using System.IO;
    using System.Collections.Generic;
    using System.Net.Http;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;
    using enigma;
    using System.Text;
    using Ser.Api;
    using System.Net.WebSockets;
    using System.Threading;
    using Qlik.EngineAPI;
    using ImpromptuInterface;
    #endregion

    #region Enumeration
    public enum QlikAppMode
    {
        DESKTOP,
        SERVER
    }
    #endregion

    public class QlikConnection
    {
        #region Logger
        private static Logger logger = LogManager.GetCurrentClassLogger();
        #endregion

        #region Properties & Variables
        public Uri ConnectUri { get; private set; }
        public SerConnection Config { get; private set; }
        public Cookie ConnectCookie { get; private set; }
        public IDoc CurrentApp { get; private set; }
        public QlikAppMode Mode { get; private set; }
        public bool IsFree { get; set; } = false;
        public string Identity { get; set; } = null;
        public string ConnId { get; set; } = Guid.NewGuid().ToString();
        private bool IsSharedSession { get; set; }
        private Session SocketSession = null;
        private readonly object lockObject = new object();
        #endregion

        #region Constructor & Init
        public QlikConnection(string identity, SerConnection config)
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback += (a, b, c, d) => { return true; };

            Mode = QlikAppMode.SERVER;
            IsSharedSession = true;
            Config = config;
            Identity = identity;

            var connectUrl = SwitchScheme(Config.ServerUri.AbsoluteUri);
            var appurl = Uri.EscapeDataString(SenseUtilities.GetFullAppName(Config.App).TrimStart('/'));
            connectUrl = $"{connectUrl}/app/{appurl}";

            if (identity == null)
            {
                connectUrl = $"{connectUrl}/identity/{Guid.NewGuid().ToString()}";
                IsSharedSession = false;
            }
            else if (!String.IsNullOrEmpty(identity))
            {
                connectUrl = $"{connectUrl}/identity/{identity}";
            }

            ConnectUri = new Uri(connectUrl);
            logger.Info($"Create Qlik connection {ConnId} to {connectUrl} with app {Config.App} and identity {identity}.");
        }
        #endregion

        #region Private Methods
        private string SwitchScheme(string value)
        {
            value = value.Replace("http://", "ws://");
            value = value.Replace("https://", "wss://");
            return value.TrimEnd('/');
        }

        private string GetAppId(IGlobal global)
        {
            if (Guid.TryParse(Config.App, out var result))
                return Config.App;

            dynamic results = global.GetDocListAsync<JArray>().Result;
            foreach (var app in results)
            {
                if (app.qDocName.Value == Config.App)
                    return app.qDocId;
            }
            return Config.App;
        }

        private Cookie GetCookie(ConnectionOptions options)
        {
            try
            {
                if (ConnectCookie != null)
                    return ConnectCookie;
                var qlikCookieConnection = BuildQrsUri(ConnectUri, Config.ServerUri);
                var newUri = new UriBuilder(qlikCookieConnection);
                newUri.Path += "/sense/app";
                var connectUri = newUri.Uri;
                logger.Debug($"Http ConnectUri: {connectUri}");
                var cookieContainer = new CookieContainer();

                X509Certificate2 qlikClientCert = null;
                if (options.UseCertificate)
                    qlikClientCert = options.GetQlikClientCertificate();

#if NET452 || NET462
                var webHandler = new WebRequestHandler
                {
                    UseDefaultCredentials = true,
                    CookieContainer = cookieContainer,
                };
                if (qlikClientCert != null)
                    webHandler.ClientCertificates.Add(qlikClientCert);

                var callback = ServicePointManager.ServerCertificateValidationCallback;
                if (callback == null)
                    throw new NotImplementedException(".NET has no certificate check");
                var connection = new HttpClient(webHandler);
#else
                var handler = new HttpClientHandler
                {
                    UseDefaultCredentials = true,
                    CookieContainer = cookieContainer,
                };
                if (qlikClientCert != null)
                    handler.ClientCertificates.Add(qlikClientCert);
                handler.ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
                {
                    return true;
                };
                var connection = new HttpClient(handler);
#endif
                if (!String.IsNullOrEmpty(options.HeaderName))
                    connection.DefaultRequestHeaders.Add(options.HeaderName, options.HeaderValue);
                var message = connection.GetAsync(connectUri).Result;
                logger.Debug($"Http connection message: {message}");

                var responseCookies = cookieContainer?.GetCookies(connectUri)?.Cast<Cookie>() ?? null;
                var cookie = responseCookies.FirstOrDefault(c => c.Name.Equals(options.CookieName)) ?? null;
                if (cookie != null)
                {
                    logger.Debug($"The session cookie {cookie?.Name}={cookie?.Value} was generated.");
                    return cookie;
                }
                else
                    throw new Exception("No connection to qlik");
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Can´t create a qlik session cookie.");
                return null;
            }
        }
        #endregion

        #region Public Methods
        public static Uri BuildQrsUri(Uri connectUrl, Uri baseUrl)
        {
            var virtualProxy = baseUrl?.PathAndQuery?.Split(new char[] { '/' },
                           StringSplitOptions.RemoveEmptyEntries)?.FirstOrDefault() ?? null;
            virtualProxy = $"/{virtualProxy}";

            var qrsBuilder = new UriBuilder()
            {
                Host = connectUrl.Host,
                Path = virtualProxy
            };
            switch (connectUrl.Scheme)
            {
                case "ws":
                    qrsBuilder.Scheme = "http";
                    qrsBuilder.Port = connectUrl.Port;
                    break;
                case "wss":
                    qrsBuilder.Scheme = "https";
                    qrsBuilder.Port = connectUrl.Port;
                    break;
                default:
                    qrsBuilder.Scheme = "https";
                    break;
            }
            return qrsBuilder.Uri;
        }

        public bool Connect()
        {
            try
            {
                logger.Info($"Connect to: {ConnectUri.AbsoluteUri}");
                var config = new EnigmaConfigurations()
                {
                    Url = ConnectUri.AbsoluteUri,
                    CreateSocket = async (Url) =>
                    {
                        var webSocket = new ClientWebSocket();
                        webSocket.Options.Cookies = new CookieContainer();
#if NET452
                        var callback = ServicePointManager.ServerCertificateValidationCallback;
                        if (callback == null)
                        throw new NotImplementedException(".NET has no certificate check");
#elif NET462
                        var callback = ServicePointManager.ServerCertificateValidationCallback;
                        if (callback == null)
                        throw new NotImplementedException(".NET has no certificate check");
#else
                        webSocket.Options.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
#endif
                        var credentials = Config?.Credentials ?? null;
                        var credType = Config?.Credentials?.Type ?? QlikCredentialType.NONE;
                        switch (credType)
                        {
                            case QlikCredentialType.CERTIFICATE:
                                var options = new ConnectionOptions()
                                {
                                    CertificatePath = credentials?.Cert ?? null,
                                    UseCertificate = true,
                                };
                                var clientCert = options.GetQlikClientCertificate();
                                var certCollect = new X509Certificate2Collection(clientCert);
                                ConnectCookie = GetCookie(options);
                                webSocket.Options.Cookies.Add(ConnectCookie);
                                logger.Debug($"Credential type: {credentials?.Type}");
                                break;
                            case QlikCredentialType.WINDOWSAUTH:
                                webSocket.Options.Credentials = new NetworkCredential(credentials?.Key, credentials?.Value);
                                logger.Debug($"WinAuth type: {credentials?.Type} with User {credentials?.Key}");
                                break;
                            case QlikCredentialType.SESSION:
                                logger.Debug($"Session-Cookie {credentials?.Key}={credentials?.Value}.");
                                ConnectCookie = new Cookie(credentials?.Key, credentials?.Value)
                                {
                                    Secure = true,
                                    Domain = ConnectUri.Host,
                                    Path = "/",
                                };
                                webSocket.Options.Cookies.Add(ConnectCookie);
                                logger.Debug($"Session type: {credentials?.Type} with Session {credentials?.Value}");
                                break;
                            case QlikCredentialType.JWT:
                                logger.Debug($"Jwt type: {credentials?.Key} - {credentials?.Value}.");
                                options = new ConnectionOptions()
                                {
                                    HeaderName = credentials?.Key,
                                    HeaderValue = credentials?.Value,
                                };
                                ConnectCookie = GetCookie(options);
                                webSocket.Options.Cookies.Add(ConnectCookie);
                                break;
                            case QlikCredentialType.HEADER:
                                logger.Debug($"Header type: {credentials?.Key} - {credentials?.Value}.");
                                options = new ConnectionOptions()
                                {
                                    HeaderName = credentials?.Key,
                                    HeaderValue = credentials?.Value,
                                };
                                ConnectCookie = GetCookie(options);
                                webSocket.Options.Cookies.Add(ConnectCookie);
                                break;
                            case QlikCredentialType.NONE:
                                logger.Debug($"None type: No Authentication.");
                                // No Authentication for DESKTOP and DOCKER
                                break;
                            default:
                                throw new Exception("Unknown Qlik connection type.");
                        }
                        webSocket.Options.KeepAliveInterval = TimeSpan.FromDays(48);
                        await webSocket.ConnectAsync(new Uri(Url), CancellationToken.None);
                        return webSocket;
                    },
                };

                SocketSession = Enigma.Create(config);
                var globalTask = SocketSession.OpenAsync();
                globalTask.Wait();
                IGlobal global = Impromptu.ActLike<IGlobal>(globalTask.Result);
                var task = global.IsDesktopModeAsync();
                task.Wait(2500);
                if (!task.IsCompleted)
                    throw new Exception("No connection to qlik.");
                if (task.Result)
                    Mode = QlikAppMode.DESKTOP;
                logger.Debug($"Use connection mode: {Mode}");
                if (IsSharedSession)
                {
                    try
                    {
                        CurrentApp = global.GetActiveDocAsync().Result;
                    }
                    catch (Exception ex)
                    {
                        logger.Error(ex, "No existing shared session found. Please open the app in the browser.");
                        return false;
                    }
                }
                else
                {
                    var appName = String.Empty;
                    if (Mode == QlikAppMode.DESKTOP)
                        appName = SenseUtilities.GetFullAppName(Config.App);
                    else
                        appName = GetAppId(global);
                    logger.Debug($"Connect with app name: {appName}");
                    CurrentApp = global.OpenDocAsync(appName).Result;
                }
                logger.Debug("The Connection to Qlik was successfully");
                return true;
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"The connection to Qlik Sense with uri \"{ConnectUri}\" app \"{Config.App}\" could not be established.");
                return false;
            }
        }

        public void Close()
        {
            try
            {
                lock (lockObject)
                {
                    if (SocketSession != null)
                    {
                        SocketSession.CloseAsync().Wait(100);
                        SocketSession = null;
                        logger.Debug($"The connection {ConnId} - Uri {ConnectUri?.AbsoluteUri} will be released.");
                    }
                }
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"The connection {ConnId} - Uri {ConnectUri?.AbsoluteUri} could not release.");
            }
        }
        #endregion
    }
}