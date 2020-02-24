﻿namespace Q2g.HelperQlik
{
    #region Usings
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using NLog;
    using enigma;
    using Newtonsoft.Json;
    using System.Threading;
    using System.Collections.Concurrent;
    #endregion

    public class ConnectionManager
    {
        #region Logger
        private static Logger logger = LogManager.GetCurrentClassLogger();
        #endregion

        #region Variables && Properties
        private ConcurrentDictionary<string, Connection> Connections = new ConcurrentDictionary<string, Connection>();
        private readonly object threadObject = new object();
        private int emergencyConnectionCount = 0;
        private bool canConnect = true;
        #endregion

        #region Private Methods
        public Connection FindConnection(ConnectionConfig config)
        {
            try
            {
                var values = Connections.Values.ToArray();
                foreach (var conn in values)
                {
                    if (conn.IsFree == true)
                    {
                        logger.Trace("The connection is checked for reuse.");
                        logger.Trace($"App \"{conn?.Config?.App}={config?.App}\"");
                        logger.Trace($"Uri: \"{conn?.Config?.ServerUri?.AbsoluteUri}={config?.ServerUri?.AbsoluteUri}\"");
                        logger.Trace($"Identity: \"{conn?.Identity}={String.Join(",", config?.Identities ?? new List<string>())}\"");
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

        private bool Connect(Connection connection)
        {
            try
            {
                if (!canConnect)
                    return false;

                if (connection.Connect())
                {
                    Connections.TryAdd(connection.ConnId, connection);
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
        public void MakeFree()
        {
            try
            {
                logger.Debug("Make connections free.");
                var activeConnections = Connections.Values.ToArray();
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

        public ConnectionConfig GetConnConfig(ConnectionConfig config, string serverUri = null, string appName = null)
        {
            var jsonSerConfig = JsonConvert.SerializeObject(config);
            var configCopy = JsonConvert.DeserializeObject<ConnectionConfig>(jsonSerConfig);
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

        public static Connection NewConnection(ConnectionConfig connectionConfig, bool loadPossibleApps = false)
        {
            try
            {
                var distinctIdentities = connectionConfig?.Identities?.Distinct()?.ToArray() ?? new string[0];
                foreach (var identity in distinctIdentities)
                {
                    var newConnection = new Connection(identity, connectionConfig);
                    if (newConnection.Connect(loadPossibleApps))
                    {
                        newConnection.IsFree = false;
                        return newConnection;
                    }
                }

                if (connectionConfig.Identities == null || connectionConfig.Identities.Count == 0)
                {
                    var conn = new Connection(null, connectionConfig);
                    if (conn.Connect(loadPossibleApps))
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

        public int LoadConnections(List<ConnectionConfig> connectionConfigs, int coreCount)
        {
            try
            {
                lock (threadObject)
                {
                    var connCount = 0;
                    foreach (var connectionConfig in connectionConfigs)
                    {
                        var distinctIdentities = connectionConfig?.Identities?.Distinct()?.ToArray() ?? new string[0];
                        foreach (var identity in distinctIdentities)
                        {
                            if (Connections.Count < coreCount)
                            {
                                var newConnection = new Connection(identity, connectionConfig);
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
            }
            catch (Exception ex)
            {
                logger.Error(ex, "No connections load.");
                return 1;
            }
        }

        public Connection GetConnection(List<ConnectionConfig> connectionConfigs, CancellationToken? token = null)
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
                            var newConnection = new Connection(null, connectionConfig);
                            if (Connect(newConnection))
                            {
                                logger.Debug($"Connection count {Connections.Count}.");
                                return newConnection;
                            }
                            else
                            {
                                if (token.HasValue)
                                    if (token.Value.IsCancellationRequested)
                                        throw new Exception("No connection - Canceled by user.");

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