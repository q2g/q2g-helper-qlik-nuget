namespace Q2g.HelperQlik
{
    #region Usings
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Reflection;
    using System.Text;
    using System.Web;
    using enigma;
    using NLog;
    #endregion

    public class HelperUtilities
    {
        #region Logger
        private static Logger logger = LogManager.GetCurrentClassLogger();
        #endregion

        #region Private Methods
        private static string GetQueryString(Dictionary<string, string> urlParams)
        {
            var builder = new StringBuilder();
            foreach (var urlParam in urlParams)
                builder.Append($"{urlParam.Key}={urlParam.Value}&");
            return builder.ToString().TrimEnd('&');
        }
        #endregion

        #region Public Methods
        public static string BuildUrl(UrlConfig urlConfig = null)
        {
            try
            {
                if (urlConfig == null)
                    urlConfig = new UrlConfig();

                var urlBuilder = new StringBuilder();
                urlBuilder.Append(urlConfig.Secure ? "wss" : "ws");
                urlBuilder.Append("://");
                urlBuilder.Append($"{urlConfig.Host}");

                if (String.IsNullOrEmpty(urlConfig.AppId) && String.IsNullOrEmpty(urlConfig.Route))
                    urlConfig.Route = "app/engineData";

                urlBuilder.Append(urlConfig?.Port > 0 ? $":{urlConfig?.Port}" : "");
                urlBuilder.Append(String.IsNullOrEmpty(urlConfig?.Prefix) ? $"{urlConfig?.Prefix?.Trim('/')}" : "");
                urlBuilder.Append(String.IsNullOrEmpty(urlConfig?.SubPath) ? $"{urlConfig?.SubPath?.Trim('/')}" : "");

                if (!String.IsNullOrEmpty(urlConfig?.Route))
                    urlBuilder.Append($"/{urlConfig?.Route?.Trim('/')}");
                else if (!String.IsNullOrEmpty(urlConfig?.AppId))
                    urlBuilder.Append($"/app/{HttpUtility.UrlEncode(urlConfig?.AppId)}");
                if (!String.IsNullOrEmpty(urlConfig?.Identity))
                    urlBuilder.Append($"/identity/{HttpUtility.UrlEncode(urlConfig?.Identity)}");
                if (urlConfig.Ttl >= 0)
                    urlBuilder.Append($"/ttl/{urlConfig?.Ttl}/");
                if (urlConfig.UrlParams.Count > 0)
                    urlBuilder.Append($"?{GetQueryString(urlConfig.UrlParams)}");
                return urlBuilder.ToString();
            }
            catch (Exception ex)
            {
                logger.Error(ex, "The uri could not build.");
                return null;
            }
        }

        public static string GetFullAppName(string appName)
        {
            try
            {
                if (String.IsNullOrEmpty(appName))
                    return null;
                if (Guid.TryParse(appName, out var myguid))
                    return appName;
                var fullPath = appName;
                if (!appName.ToLowerInvariant().StartsWith("%userprofile%") && !appName.Contains(":") &&
                    !appName.StartsWith("\\\\") && !appName.StartsWith("/"))
                    fullPath = $"%USERPROFILE%\\Documents\\Qlik\\Sense\\Apps\\{appName.Trim('\\')}";
                if (!Path.HasExtension(fullPath))
                    fullPath = $"{fullPath}.qvf";
                fullPath = Environment.ExpandEnvironmentVariables(fullPath);
                return fullPath;
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"The app name '{appName}' could not resolve to a full app name.");
                return null;
            }
        }

        public static string GetFullPathFromApp(string path)
        {
            try
            {
                if (String.IsNullOrEmpty(path))
                    return null;
                if (path.StartsWith("/"))
                    return path;
                if (!path.StartsWith("\\\\") && !path.Contains(":") && !path.StartsWith("%"))
                    path = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location).TrimEnd('\\'), path.TrimStart('\\'));
                path = Environment.ExpandEnvironmentVariables(path);
                return Path.GetFullPath(path);
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"The full path '{path}' of the app could not resolve.");
                return null;
            }
        }

        public static string MakeWebSocketFromHttp(Uri uri)
        {
            try
            {
                var result = uri.AbsoluteUri;
                result = result.Replace("http://", "ws://");
                result = result.Replace("https://", "wss://");
                result = result.TrimEnd('/');
                return result;
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"Make web socket from http '{uri?.ToString()}' failed.");
                return null;
            }
        }

        public static Tuple<Uri, string> NormalizeUri(string input)
        {
            try
            {
                var uri = new Uri(input);
                return new Tuple<Uri, string>(uri, uri.Host);
            }
            catch
            {
                logger.Info($"Read uri '{input}' in compatibility mode");
                var tempUri = input.Replace("://", "://host/");
                var uri = new Uri(tempUri);
                var parts = input.Split(new char[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);
                var host = uri.OriginalString.Split('/').ElementAtOrDefault(3);
                var segment = String.Join('/', parts.Skip(2)).TrimEnd('/');
                var normalUri = new Uri($"{uri.Scheme}://host/{segment}");
                return new Tuple<Uri, string>(normalUri, host);
            }
        }

        public static string GetFullQualifiedHostname(int timeout)
        {
            try
            {
                var serverName = Environment.MachineName;
                var result = Dns.BeginGetHostEntry(serverName, null, null);
                if (result.AsyncWaitHandle.WaitOne(timeout, true))
                    return Dns.EndGetHostEntry(result).HostName;
                else
                    return Environment.MachineName;
            }
            catch (Exception ex)
            {
                logger.Error(ex, "No full qualified hostname from server found.");
                return Environment.MachineName;
            }
        }

        public static IPAddress GetServerIp(int timeout)
        {
            try
            {
                var hostName = GetFullQualifiedHostname(timeout);
                var result = Dns.GetHostEntry(hostName).AddressList.FirstOrDefault(a =>
                           a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                return result;
            }
            catch (Exception ex)
            {
                logger.Error(ex, "No ip from server found.");
                return null;
            }
        }
        #endregion
    }
}