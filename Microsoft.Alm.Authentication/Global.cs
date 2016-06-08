using System;

namespace Microsoft.Alm.Authentication
{
    public static class Global
    {
        private static string _useragent = null;

        /// <summary>
        /// Creates the correct user-agent string for HTTP calls.
        /// </summary>
        /// <returns>The `user-agent` string for "git-tools".</returns>
        public static string GetUserAgent(string defaultAgent = "CodeFlow")
        {
            if (_useragent == null)
            {
                Version version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                _useragent = String.Format("{0} ({1}; {2}; {3}) CLR/{4} Review-tools/{5}",
                                           defaultAgent,
                                           Environment.OSVersion.VersionString,
                                           Environment.OSVersion.Platform,
                                           Environment.Is64BitOperatingSystem ? "x64" : "x86",
                                           Environment.Version.ToString(3),
                                           version.ToString(3));
            }
            return _useragent;
        }
    }
}
