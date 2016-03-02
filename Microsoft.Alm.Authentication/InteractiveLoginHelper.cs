namespace Microsoft.Alm.Authentication
{
    using System;
    using System.Runtime.InteropServices;
    using System.Text;

    public class InteractiveLoginHelper
    {
        public static string Title = "";

        public static bool GithubCredentialModalPrompt(TargetUri targetUri, out string username, out string password)
        {
            return ModalPromptForCredentials(targetUri, out username, out password);
        }

        public static bool GithubAuthcodeModalPrompt(TargetUri targetUri, GithubAuthenticationResultType resultType, string username, out string authenticationCode)
        {
            authenticationCode = null;

            string type =
                resultType == GithubAuthenticationResultType.TwoFactorApp
                    ? "app"
                    : "sms";
            string message = String.Format("Enter {0} authentication code for {1}://{2}.", type, targetUri.Scheme, targetUri.DnsSafeHost);

            return ModalPromptForPassword(targetUri, message, username, out authenticationCode);
        }

        private static bool ModalPromptForPassword(TargetUri targetUri, string message, string username, out string password)
        {
            NativeMethodsForInteractiveLogin.CredentialUiInfo credUiInfo = new NativeMethodsForInteractiveLogin.CredentialUiInfo
            {
                BannerArt = IntPtr.Zero,
                CaptionText = Title,
                MessageText = message,
                Parent = IntPtr.Zero,
                Size = Marshal.SizeOf(typeof(NativeMethodsForInteractiveLogin.CredentialUiInfo))
            };
            NativeMethodsForInteractiveLogin.CredentialUiWindowsFlags flags = NativeMethodsForInteractiveLogin.CredentialUiWindowsFlags.Generic;
            NativeMethodsForInteractiveLogin.CredentialPackFlags authPackage = NativeMethodsForInteractiveLogin.CredentialPackFlags.None;
            IntPtr packedAuthBufferPtr = IntPtr.Zero;
            IntPtr inBufferPtr = IntPtr.Zero;
            uint packedAuthBufferSize = 0;
            bool saveCredentials = false;
            int inBufferSize = 0;

            try
            {
                int error;

                // execute with `null` to determine buffer size
                // always returns false when determining size, only fail if `inBufferSize` looks bad
                NativeMethodsForInteractiveLogin.CredPackAuthenticationBuffer(flags: authPackage,
                                                                              username: username,
                                                                              password: String.Empty,
                                                                              packedCredentials: inBufferPtr,
                                                                              packedCredentialsSize: ref inBufferSize);
                if (inBufferSize <= 0)
                {
                    error = Marshal.GetLastWin32Error();
                    username = null;
                    password = null;

                    return false;
                }

                inBufferPtr = Marshal.AllocHGlobal(inBufferSize);

                if (!NativeMethodsForInteractiveLogin.CredPackAuthenticationBuffer(flags: authPackage,
                                                                                   username: username,
                                                                                   password: String.Empty,
                                                                                   packedCredentials: inBufferPtr,
                                                                                   packedCredentialsSize: ref inBufferSize))
                {
                    error = Marshal.GetLastWin32Error();
                    username = null;
                    password = null;

                    return false;
                }

                return ModalPromptDisplayDialog(ref credUiInfo,
                                                ref authPackage,
                                                packedAuthBufferPtr,
                                                packedAuthBufferSize,
                                                inBufferPtr,
                                                inBufferSize,
                                                saveCredentials,
                                                flags,
                                                out username,
                                                out password);
            }
            finally
            {
                if (inBufferPtr != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(inBufferPtr);
                }
            }
        }

        private static bool ModalPromptForCredentials(TargetUri targetUri, out string username, out string password)
        {
            string message = String.Format("Enter your credentials for {0}://{1}.", targetUri.Scheme, targetUri.DnsSafeHost);

            NativeMethodsForInteractiveLogin.CredentialUiInfo credUiInfo = new NativeMethodsForInteractiveLogin.CredentialUiInfo
            {
                BannerArt = IntPtr.Zero,
                CaptionText = Title,
                MessageText = message,
                Parent = IntPtr.Zero,
                Size = Marshal.SizeOf(typeof(NativeMethodsForInteractiveLogin.CredentialUiInfo))
            };
            NativeMethodsForInteractiveLogin.CredentialUiWindowsFlags flags = NativeMethodsForInteractiveLogin.CredentialUiWindowsFlags.Generic;
            NativeMethodsForInteractiveLogin.CredentialPackFlags authPackage = NativeMethodsForInteractiveLogin.CredentialPackFlags.None;
            IntPtr packedAuthBufferPtr = IntPtr.Zero;
            IntPtr inBufferPtr = IntPtr.Zero;
            uint packedAuthBufferSize = 0;
            bool saveCredentials = false;
            int inBufferSize = 0;

            return ModalPromptDisplayDialog(ref credUiInfo,
                                            ref authPackage,
                                            packedAuthBufferPtr,
                                            packedAuthBufferSize,
                                            inBufferPtr,
                                            inBufferSize,
                                            saveCredentials,
                                            flags,
                                            out username,
                                            out password);
        }

        private static bool ModalPromptDisplayDialog(
           ref NativeMethodsForInteractiveLogin.CredentialUiInfo credUiInfo,
           ref NativeMethodsForInteractiveLogin.CredentialPackFlags authPackage,
           IntPtr packedAuthBufferPtr,
           uint packedAuthBufferSize,
           IntPtr inBufferPtr,
           int inBufferSize,
           bool saveCredentials,
           NativeMethodsForInteractiveLogin.CredentialUiWindowsFlags flags,
           out string username,
           out string password)
        {
            int error;

            try
            {
                // open a standard Windows authentication dialog to acquire username + password credentials
                if ((error = NativeMethodsForInteractiveLogin.CredUIPromptForWindowsCredentials(credInfo: ref credUiInfo,
                                                                                                authError: 0,
                                                                                                authPackage: ref authPackage,
                                                                                                inAuthBuffer: inBufferPtr,
                                                                                                inAuthBufferSize: (uint)inBufferSize,
                                                                                                outAuthBuffer: out packedAuthBufferPtr,
                                                                                                outAuthBufferSize: out packedAuthBufferSize,
                                                                                                saveCredentials: ref saveCredentials,
                                                                                                flags: flags)) != NativeMethods.Win32Error.Success)
                {
                    username = null;
                    password = null;

                    return false;
                }

                // use `StringBuilder` references instead of string so that they can be written to
                StringBuilder usernameBuffer = new StringBuilder(512);
                StringBuilder domainBuffer = new StringBuilder(256);
                StringBuilder passwordBuffer = new StringBuilder(512);
                int usernameLen = usernameBuffer.Capacity;
                int passwordLen = passwordBuffer.Capacity;
                int domainLen = domainBuffer.Capacity;

                // unpack the result into locally useful data
                if (!NativeMethodsForInteractiveLogin.CredUnPackAuthenticationBuffer(flags: authPackage,
                                                                                     authBuffer: packedAuthBufferPtr,
                                                                                     authBufferSize: packedAuthBufferSize,
                                                                                     username: usernameBuffer,
                                                                                     maxUsernameLen: ref usernameLen,
                                                                                     domainName: domainBuffer,
                                                                                     maxDomainNameLen: ref domainLen,
                                                                                     password: passwordBuffer,
                                                                                     maxPasswordLen: ref passwordLen))
                {
                    username = null;
                    password = null;
                    error = Marshal.GetLastWin32Error();

                    return false;
                }

                username = usernameBuffer.ToString();
                password = passwordBuffer.ToString();

                return true;
            }
            finally
            {
                if (packedAuthBufferPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(packedAuthBufferPtr);
                }
            }
        }

    }
}
