namespace Q2g.HelperQlik
{
    #region Usings
    using Newtonsoft.Json;
    using Ser.Api;
    #endregion

    #region Interfaces
    /// <summary>
    /// Qlik authentication type
    /// </summary>
    public interface IQlikCredentials
    {
        /// <summary>
        /// Qlik authentication type
        /// </summary>
        QlikCredentialType Type { get; }
    }
    #endregion

    /// <summary>
    /// Logic for certificate authentication
    /// </summary>
    public class CertificateAuth : IQlikCredentials
    {
        #region Properties & Variables
        /// <summary>
        /// Qlik authentication type
        /// </summary>
        [JsonIgnore]
        public QlikCredentialType Type { get; } = QlikCredentialType.CERTIFICATE;

        /// <summary>
        /// Path to the qlik server certificates
        /// </summary>
        [JsonProperty(nameof(CertificatePath))]
        public string CertificatePath { get; private set; }

        /// <summary>
        /// Qlik UserId
        /// </summary>
        [JsonProperty(nameof(UserId))]
        public string UserId { get; private set; }

        /// <summary>
        /// Qlik UserDirectory
        /// </summary>
        [JsonProperty(nameof(UserDirectory))]
        public string UserDirectory { get; private set; }

        /// <summary>
        /// Password of the certificate which can be specified when generating
        /// </summary>
        [JsonProperty(nameof(CertPassword))]
        public string CertPassword { get; private set; }
        #endregion
    }

    /// <summary>
    /// Logic for windows authentication
    /// </summary>
    public class WindowsAuth : IQlikCredentials
    {
        #region Properties & Variables
        /// <summary>
        /// Qlik authentication type
        /// </summary>
        [JsonIgnore]
        public QlikCredentialType Type { get; } = QlikCredentialType.WINDOWSAUTH;

        /// <summary>
        /// windows account name
        /// </summary>
        [JsonProperty(nameof(Login))]
        public string Login { get; set; }


        /// <summary>
        /// windows account password
        /// </summary>
        [JsonProperty(nameof(Password))]
        public string Password { get; set; }
        #endregion
    }

    /// <summary>
    /// The Session authentication class
    /// </summary>
    public class SessionAuth : IQlikCredentials
    {
        #region Properties & Variables
        /// <summary>
        /// Qlik authentication type
        /// </summary>
        [JsonIgnore]
        public QlikCredentialType Type { get; } = QlikCredentialType.SESSION;

        /// <summary>
        /// The name of the cookie (Default: XQlik-Session)
        /// </summary>
        [JsonProperty(nameof(CookieName))]
        public string CookieName { get; set; }

        /// <summary>
        /// The value of the cookie
        /// </summary>
        [JsonProperty(nameof(CookieValue))]
        public string CookieValue { get; set; }
        #endregion
    }
}