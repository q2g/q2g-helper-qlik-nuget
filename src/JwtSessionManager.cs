﻿namespace Q2g.HelperQlik
{
    #region Usings
    using System;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Security.Cryptography.X509Certificates;
    using NLog;
    using Q2g.HelperPem;
    using Ser.Api;
    using Ser.Api.Model;
    #endregion

    public class JwtSessionManager
    {
        #region Logger
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        #endregion

        #region Public Methods
        public Cookie GetJWTSession(Uri connectUri, string token, string cookieName = "X-Qlik-Session")
        {
            try
            {
                var newUri = new UriBuilder(connectUri);
                newUri.Path = $"{newUri.Path.Trim('/')}/sense/app";
                logger.Debug($"ConnectUri: {connectUri}");
                var fullConnectUri = newUri.Uri;
                logger.Debug($"Connection to uri: {fullConnectUri}");
                var cookieContainer = new CookieContainer();
                var connectionHandler = new HttpClientHandler
                {
                    UseDefaultCredentials = true,
                    CookieContainer = cookieContainer,
                };

                connectionHandler.ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
                {
                    if (ServerCertificateValidation.Validate(sender, certificate, sslPolicyErrors))
                        return true;
                    ServerCertificateValidation.ReadAlternativeDnsNames(connectUri, certificate);
                    return false;
                };

                var connection = new HttpClient(connectionHandler);
                connection.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
                var message = connection.GetAsync(fullConnectUri).Result;
                logger.Trace($"Message: {message}");

                var responseCookies = cookieContainer?.GetCookies(fullConnectUri)?.Cast<Cookie>() ?? null;
                var cookie = responseCookies.FirstOrDefault(c => c.Name.Equals(cookieName)) ?? null;
                logger.Debug($"The session cookie was found. {cookie?.Name} - {cookie?.Value}");
                return cookie;
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Can´t create session cookie with JWT.");
                return null;
            }
        }

        public string GetToken(DomainUser domainUser, SerConnection connection, TimeSpan untilValid)
        {
            try
            {
                var cert = new X509Certificate2();
                var certPath = HelperUtilities.GetFullPathFromApp(connection.Credentials.Cert);
                logger.Debug($"CERTPATH: {certPath}");
                var privateKey = HelperUtilities.GetFullPathFromApp(connection.Credentials.PrivateKey);
                logger.Debug($"PRIVATEKEY: {privateKey}");
                cert = cert.LoadPem(certPath, privateKey);
                var claims = new[]
                {
                    new Claim("UserDirectory",  domainUser.UserDirectory),
                    new Claim("UserId", domainUser.UserId),
                    new Claim("Attributes", "[SerOnDemand]")
                }.ToList();
                return cert.GenerateQlikJWToken(claims, untilValid);
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Can´t create a jwt token.");
                return null;
            }
        }

        public SessionInfo CreateNewSession(SerConnection connection, DomainUser qlikUser, string appId)
        {
            try
            {
                var token = GetToken(qlikUser, connection, TimeSpan.FromMinutes(20));
                logger.Debug($"Generate token {token}");
                var cookie = GetJWTSession(connection.ServerUri, token, connection.Credentials.Key);
                logger.Debug($"Generate cookie {cookie?.Name} - {cookie?.Value}");
                if (cookie != null)
                {
                    var sessionInfo = new SessionInfo()
                    {
                        Cookie = cookie,
                        ConnectUri = connection.ServerUri,
                        AppId = appId,
                        User = qlikUser,
                    };
                    return sessionInfo;
                }
                return null;
            }
            catch (Exception ex)
            {
                logger.Error(ex, "The session could not be created.");
                return null;
            }
        }

        public void MakeSocketFree(SessionInfo session)
        {
            try
            {
                logger.Debug($"The web socket '{session?.AppId ?? null}' connection is released.");
                if (session?.QlikConn != null)
                {
                    session.QlikConn.Close();
                    session.QlikConn = null;
                }
            }
            catch (Exception ex)
            {
                throw new Exception("The session could not close.", ex);
            }
        }
        #endregion
    }

    #region Helper Classes
    public class SessionInfo
    {
        #region Properties
        public DomainUser User { get; set; }
        public string AppId { get; set; }
        public Cookie Cookie { get; set; }
        public Uri ConnectUri { get; set; }
        public Q2g.HelperQlik.Connection QlikConn { get; set; }
        #endregion
    }
    #endregion
}