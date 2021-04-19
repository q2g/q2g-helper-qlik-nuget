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
    using System.Security.Cryptography.X509Certificates;
    using Ser.Api.Model;
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
        private readonly static Logger logger = LogManager.GetCurrentClassLogger();
        #endregion

        #region Properties & Variables
        public Uri ConnectUri { get; private set; }
        public SerConnection Config { get; private set; }
        public Cookie ConnectCookie { get; private set; }
        public X509Certificate2 ConnectCertificate { get; private set; }
        public IDoc CurrentApp { get; private set; }
        public QlikAppMode Mode { get; private set; }
        public bool IsFree { get; set; } = false;
        public string Identity { get; set; }
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
                var newIdentity = Guid.NewGuid();
                connectUrl = $"{connectUrl}/identity/{newIdentity}";
                IsSharedSession = false;
                Identity = newIdentity.ToString();
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
            if (Guid.TryParse(Config.App, out _))
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
            Console.WriteLine($"Message: {message}");
            IEnumerable<Cookie> responseCookies = cookieContainer.GetCookies(serverUri).Cast<Cookie>();
            return responseCookies.First(cookie => cookie.Name.Equals(cookieName));
        }
        #endregion

        #region Public Methods
        public static Uri BuildQrsUri(Uri connectUrl, Uri baseUrl, int? port = null)
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

            if (port.HasValue)
                qrsBuilder.Port = port.Value;

            return qrsBuilder.Uri;
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
                        logger.Debug($"Connection type is '{credType}'");
                        switch (credType)
                        {
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
                                var keyValue = credentials?.Value ?? null;
                                webSocket.Options.SetRequestHeader(keyName, keyValue);
                                logger.Warn($"JWT is not supported - The SER connector resolve the bearer token!!!");
                                break;
                            case QlikCredentialType.CLOUD:
                                logger.Debug($"Connecting to Qlik Cloud.");
                                logger.Debug($"Cloud type: {credentials?.Key} - {credentials?.Value}.");
                                webSocket.Options.SetRequestHeader(credentials?.Key, credentials?.Value);
                                break;
                            case QlikCredentialType.NEWSESSION:
                                logger.Debug($"Connecting to Qlik with a new Session.");
                                logger.Debug($"Session infos: {credentials?.Key} - {credentials?.Value}.");
                                var jwtSession = new JwtSessionManager();
                                var newSession = jwtSession.CreateNewSession(Config, new DomainUser(credentials?.Value), Config.App);
                                ConnectCookie = newSession.Cookie;
                                webSocket.Options.Cookies.Add(ConnectCookie);
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