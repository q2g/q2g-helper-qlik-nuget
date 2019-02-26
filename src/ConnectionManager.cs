#region License
/*
Copyright (c) 2018 Konrad Mattheis und Martin Berthold
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#endregion

namespace Ser.Connections
{
    #region Usings
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Ser.Api;
    using NLog;
    using enigma;
    using Newtonsoft.Json;
    using System.Threading;
    using System.Collections.Concurrent;
    #endregion

    public static class ConnectionManager
    {
        #region Logger
        private static Logger logger = LogManager.GetCurrentClassLogger();
        #endregion

        #region Variables && Properties
        private static ConcurrentBag<QlikConnection> Connections = new ConcurrentBag<QlikConnection>();
        private static readonly object threadObject = new object();
        private static int emergencyConnectionCount = 0;
        private static bool canConnect = true;
        #endregion

        #region Private Methods
        public static QlikConnection FindConnection(SerConnection config)
        {
            try
            {
                var connections = Connections.ToArray();
                foreach (var conn in connections)
                {
                    if (conn.IsFree == true)
                    {
                        logger.Trace("The connection is checked for reuse.");
                        logger.Trace($"App \"{conn?.Config?.App}={config?.App}\"");
                        logger.Trace($"Uri: \"{conn?.Config?.ServerUri?.AbsoluteUri}={config?.ServerUri?.AbsoluteUri}\"");
                        logger.Trace($"Identity: \"{conn?.Identity}={String.Join(',', config?.Identities ?? new List<string>())}\"");
                        if (conn.Config.App == config.App && conn.Config.ServerUri.AbsoluteUri == config.ServerUri.AbsoluteUri)
                        {
                            if (config.Identities == null && conn.Identity == null)
                            {
                                conn.IsFree = false;
                                return conn;
                            }
                            var identity = config.Identities?.FirstOrDefault(i => i == conn.Identity) ?? null;
                            if (identity != null)
                            {
                                conn.IsFree = false;
                                return conn;
                            }
                        }
                    }
                }
                return null;
            }
            catch (Exception ex)
            {
                logger.Error(ex, "The connection could not find.");
                return null;
            }
        }

        private static bool Connect(QlikConnection connection)
        {
            try
            {
                if (!canConnect)
                    return false;

                if (connection.Connect())
                {
                    Connections.Add(connection);
                    return true;
                }

                canConnect = false;
                var config = connection.Config;
                logger.Error($"The connection could not created - uri {config?.ServerUri?.AbsoluteUri} and app id \"{config?.App}\".");
                return false;
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"The connection could not created  - error by connection.");
                return false;
            }
        }
        #endregion

        #region Public Methods
        public static void MakeFree()
        {
            try
            {
                logger.Debug("Make connections free.");
                var activeConnections = Connections.ToArray();
                foreach (var connection in activeConnections)
                {
                    try
                    {
                        connection.Close();
                    }
                    catch (Exception ex)
                    {
                        logger.Error(ex, $"The connection {connection?.ConnId} could not close.");
                    }
                }
                Connections.Clear();
                canConnect = true;
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Make free failed.");
            }
        }

        public static SerConnection GetConnConfig(SerConnection config, string serverUri = null, string appName = null)
        {
            var jsonSerConfig = JsonConvert.SerializeObject(config);
            var configCopy = JsonConvert.DeserializeObject<SerConnection>(jsonSerConfig);
            if (!String.IsNullOrEmpty(serverUri))
            {
                if (!Uri.TryCreate(serverUri, UriKind.Absolute, out var uriResult))
                {
                    logger.Error($"The qlik server uri {serverUri} is invalid.");
                    return null;
                }
                configCopy.ServerUri = uriResult;
            }
            if (!String.IsNullOrEmpty(appName))
                configCopy.App = appName;
            configCopy.Identities = null;
            return configCopy;
        }

        public static QlikConnection NewConnection(SerConnection connectionConfig)
        {
            try
            {
                var distinctIdentities = connectionConfig?.Identities?.Distinct()?.ToArray() ?? new string[0];
                foreach (var identity in distinctIdentities)
                {
                    var newConnection = new QlikConnection(identity, connectionConfig);
                    if (Connect(newConnection))
                    {
                        newConnection.IsFree = false;
                        return newConnection;
                    }
                }

                if (connectionConfig.Identities == null || connectionConfig.Identities.Count == 0)
                {
                    var conn = new QlikConnection(null, connectionConfig);
                    if (conn.Connect())
                        return conn;
                }
                return null;
            }
            catch (Exception ex)
            {
                logger.Error(ex, "No new connection to qlik.");
                return null;
            }
        }

        public static int LoadConnections(List<SerConnection> connectionConfigs, int coreCount)
        {
            try
            {
                var connCount = 0;
                foreach (var connectionConfig in connectionConfigs)
                {
                    var distinctIdentities = connectionConfig?.Identities?.Distinct()?.ToArray() ?? new string[0];
                    foreach (var identity in distinctIdentities)
                    {
                        if (Connections.Count < coreCount)
                        {
                            var newConnection = new QlikConnection(identity, connectionConfig);
                            if (Connect(newConnection))
                            {
                                connCount++;
                                newConnection.IsFree = true;
                                logger.Debug($"Connection count {Connections.Count} to identity {identity}");
                            }
                        }
                    }
                }
                if (connCount > 0)
                    return connCount;
                return coreCount;
            }
            catch (Exception ex)
            {
                logger.Error(ex, "No connections load.");
                return 1;
            }
        }

        public static QlikConnection GetConnection(List<SerConnection> connectionConfigs)
        {
            try
            {
                lock (threadObject)
                {
                    foreach (var connectionConfig in connectionConfigs)
                    {
                        var freeConnection = FindConnection(connectionConfig);
                        if (freeConnection != null)
                        {
                            logger.Debug($"Find a exsisting connection {freeConnection.ConnId} - Uri {connectionConfig.ServerUri.AbsoluteUri} with app {connectionConfig.App} for use.");
                            return freeConnection;
                        }

                        if (connectionConfig.Identities == null || connectionConfig.Identities?.Count == 0)
                        {
                            var newConnection = new QlikConnection(null, connectionConfig);
                            if (Connect(newConnection))
                            {
                                logger.Debug($"Connection count {Connections.Count}.");
                                return newConnection;
                            }
                            else
                            {
                                if (Connections.Count > 0)
                                {
                                    logger.Warn("Emergency connection mode - Wait for free connection.");
                                    emergencyConnectionCount++;
                                    if (emergencyConnectionCount >= 50)
                                        throw new Exception("Emergency connection mode - Timeout reached.");
                                    Thread.Sleep(1000);
                                    return GetConnection(connectionConfigs);
                                }
                            }
                        }
                    }
                }

                throw new Exception("No working connection to qlik found.");
            }
            catch (Exception ex)
            {
                logger.Error(ex, "A connection to qlik could not come closer.");
                return null;
            }
        }
        #endregion
    }
}