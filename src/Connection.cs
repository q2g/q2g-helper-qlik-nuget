namespace Q2g.HelperQlik
{
    #region Usings
    using System;
    using System.Linq;
    using System.Net;
    using NLog;
    using System.Collections.Generic;
    using System.Net.Http;
    using Newtonsoft.Json.Linq;
    using enigma;
    using System.Net.WebSockets;
    using System.Threading;
    using Qlik.EngineAPI;
    using ImpromptuInterface;
    using Ser.Api;
    using System.IO;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using Q2g.HelperPem;
    #endregion

    #region Enumeration
    public enum QlikAppMode
    {
        DESKTOP,
        SERVER
    }

    public enum SchemeMode
    {
        WEB,
        WEBSOCKET
    }
    #endregion

    public class Connection
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
        public static List<DocListEntry> PossibleApps { get; private set; } = new List<DocListEntry>();

        private bool IsSharedSession { get; set; }
        private Session SocketSession = null;
        private readonly object lockObject = new object();
        #endregion

        #region Constructor & Init
        public Connection(string identity, SerConnection config)
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback += (a, b, c, d) => { return true; };

            Mode = QlikAppMode.SERVER;
            IsSharedSession = true;
            Config = config;
            Identity = identity;

            var connectUrl = SwitchScheme(Config.ServerUri.AbsoluteUri, SchemeMode.WEBSOCKET);
            var appurl = Uri.EscapeDataString(HelperUtilities.GetFullAppName(Config.App).TrimStart('/'));
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
        private string SwitchScheme(string value, SchemeMode mode)
        {
            if (mode == SchemeMode.WEBSOCKET)
            {
                value = value.Replace("http://", "ws://");
                value = value.Replace("https://", "wss://");
                return value.TrimEnd('/');
            }
            else
            {
                value = value.Replace("ws://", "http://");
                value = value.Replace("wss://", "https://");
                return value.TrimEnd('/');
            }
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

        private Cookie GetFirstSessionCookie(Uri serverUri, NetworkCredential credentials, string cookieName)
        {
            CookieContainer cookieContainer = new CookieContainer();
            var connectionHandler = new HttpClientHandler
            {
                UseDefaultCredentials = true,
                CookieContainer = cookieContainer,
                Credentials = new CredentialCache { { serverUri, "NTLM", credentials } }
            };
            connectionHandler.ServerCertificateCustomValidationCallback += (sender, cert, chain, sslPolicyErrors) => { return true; };
            var connection = new HttpClient(connectionHandler);
            connection.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36");
            var message = connection.GetAsync(serverUri).Result;
            Console.WriteLine($"Message: {message.ToString()}");
            IEnumerable<Cookie> responseCookies = cookieContainer.GetCookies(serverUri).Cast<Cookie>();
            return responseCookies.First(cookie => cookie.Name.Equals(cookieName));
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

        private string TicketRequest(string method, string server, string user, string userdirectory)
        {
            //Create URL to REST endpoint for tickets
            var url = "https://" + server + ":4243/qps/ticket";

            //Create the HTTP Request and add required headers and content in Xrfkey
            var Xrfkey = "0123456789abcdef";
            var request = (HttpWebRequest)WebRequest.Create(url + "?Xrfkey=" + Xrfkey);
            // Add the method to authentication the user
            var cert = new X509Certificate2();
            cert = cert.GetQlikClientCertificate();
            request.ClientCertificates.Add(cert);
            request.Method = method;
            request.Accept = "application/json";
            request.Headers.Add("X-Qlik-Xrfkey", Xrfkey);
            var body = "{ 'UserId':'" + user + "','UserDirectory':'" + userdirectory + "','Attributes': []}";
            byte[] bodyBytes = Encoding.UTF8.GetBytes(body);

            if (!String.IsNullOrEmpty(body))
            {
                request.ContentType = "application/json";
                request.ContentLength = bodyBytes.Length;
                var requestStream = request.GetRequestStream();
                requestStream.Write(bodyBytes, 0, bodyBytes.Length);
                requestStream.Close();
            }

            // make the web request and return the content
            var response = (HttpWebResponse)request.GetResponse();
            var stream = response.GetResponseStream();
            return stream != null ? new StreamReader(stream).ReadToEnd() : String.Empty;
        }

        public bool Connect(bool loadPossibleApps = false)
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
                        webSocket.Options.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
                        var credentials = Config?.Credentials ?? null;
                        var credType = Config?.Credentials?.Type ?? QlikCredentialType.NONE;
                        switch (credType)
                        {
                            case QlikCredentialType.CERTIFICATE:
                                var cert = new X509Certificate2();
                                cert = cert.GetQlikClientCertificate();
                                webSocket.Options.ClientCertificates.Add(cert);
                                webSocket.Options.SetRequestHeader(credentials.Key, credentials.Value);
                                break;
                            case QlikCredentialType.WINDOWSAUTH:
                                var networkCredentials = CredentialCache.DefaultNetworkCredentials;
                                if (credentials?.Key != null && credentials?.Value != null)
                                    networkCredentials = new NetworkCredential(credentials?.Key, credentials?.Value);
                                var webUri = new Uri(SwitchScheme(ConnectUri.AbsoluteUri, SchemeMode.WEB));
                                var cookieName = "X-Qlik-Session";
                                if (credentials?.Cert != null)
                                    cookieName = credentials.Cert;
                                var webCookie = GetFirstSessionCookie(new Uri($"{webUri.Scheme}://{webUri.Host}"), networkCredentials, cookieName);
                                ConnectCookie = new Cookie(webCookie.Name, webCookie.Value)
                                {
                                    Secure = true,
                                    Domain = ConnectUri.Host,
                                    Path = "/",
                                };
                                webSocket.Options.Cookies.Add(ConnectCookie);
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
                                var keyName = credentials?.Key ?? "Authorization";
                                var keyValue = credentials?.Value ?? null; //Bearer???
                                logger.Warn($"JWT is not supported - The SER connector resolve the bearer token!!!");
                                break;
                            case QlikCredentialType.HEADER:
                                logger.Warn($"HEADER is not supported - Is too unsafe!!!");
                                break;
                            case QlikCredentialType.NONE:
                                // No Authentication for DESKTOP and DOCKER
                                logger.Debug($"None type: No Authentication.");
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
                globalTask.Wait(7500);
                if (!globalTask.IsCompleted)
                    throw new Exception("No connection to qlik.");
                IGlobal global = Impromptu.ActLike<IGlobal>(globalTask.Result);
                var task = global.IsDesktopModeAsync();
                task.Wait(2500);
                if (!task.IsCompleted)
                    throw new Exception("No connection to qlik.");
                if (task.Result)
                    Mode = QlikAppMode.DESKTOP;
                if (loadPossibleApps)
                {
                    lock (lockObject)
                    {
                        PossibleApps = global.GetDocListAsync().Result;
                    }
                }
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
                        appName = HelperUtilities.GetFullAppName(Config.App);
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