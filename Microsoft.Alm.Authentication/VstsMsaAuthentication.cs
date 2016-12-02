﻿/**** Git Credential Manager for Windows ****
 *
 * Copyright (c) Microsoft Corporation
 * All rights reserved.
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the """"Software""""), to deal
 * in the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."
**/

using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Microsoft.Alm.Authentication
{
    public sealed class VstsMsaAuthentication : BaseVstsAuthentication, IVstsMsaAuthentication
    {
        public const string DefaultAuthorityHost = AzureAuthority.AuthorityHostUrlBase + "/live.com";

        public VstsMsaAuthentication(VstsTokenScope tokenScope, ICredentialStore personalAccessTokenStore)
            : base(tokenScope, personalAccessTokenStore)
        {
            this.VstsAuthority = new VstsAzureAuthority(DefaultAuthorityHost);
        }

        /// <summary>
        /// Test constructor which allows for using fake credential stores
        /// </summary>
        /// <param name="personalAccessTokenStore"></param>
        /// <param name="adaRefreshTokenStore"></param>
        /// <param name="vstsIdeTokenCache"></param>
        /// <param name="liveAuthority"></param>
        internal VstsMsaAuthentication(
            ICredentialStore personalAccessTokenStore,
            ITokenStore vstsIdeTokenCache,
            IVstsAuthority liveAuthority)
            : base(personalAccessTokenStore,
                   vstsIdeTokenCache,
                   liveAuthority)
        { }

        /// <summary>
        /// Opens an interactive logon prompt to acquire acquire an authentication token from the
        /// Microsoft Live authentication and identity service.
        /// </summary>
        /// <param name="targetUri">
        /// The uniform resource indicator of the resource access tokens are being requested for.
        /// </param>
        /// <param name="requireCompactToken">
        /// True if a compact access token is required; false if a standard token is acceptable.
        /// </param>
        /// <returns>A <see cref="Credential"/> for packing into a basic authentication header;
        /// otherwise <see langword="null"/>.</returns>
        public async Task<Credential> InteractiveLogon(TargetUri targetUri, bool requireCompactToken)
        {
            const string QueryParameters = "domain_hint=live.com&display=popup&site_id=501454&nux=1";

            BaseSecureStore.ValidateTargetUri(targetUri);

            try
            {
                Token token;
                if ((token = await this.VstsAuthority.InteractiveAcquireToken(targetUri, this.ClientId, this.Resource, new Uri(RedirectUrl), QueryParameters)) != null)
                {
                    Git.Trace.WriteLine($"token '{targetUri}' successfully acquired.");

                    return await this.GeneratePersonalAccessToken(targetUri, token, requireCompactToken);
                }
            }
            catch (AdalException exception)
            {
                Debug.Write(exception);
            }

            Git.Trace.WriteLine($"failed to acquire token for '{targetUri}'.");
            return null;
        }

        /// <summary>
        /// Sets credentials for future use with this authentication object.
        /// </summary>
        /// <remarks>Not supported.</remarks>
        /// <param name="targetUri">
        /// The uniform resource indicator of the resource access tokens are being set for.
        /// </param>
        /// <param name="credentials">The credentials being set.</param>
        public override void SetCredentials(TargetUri targetUri, Credential credentials)
        {
            BaseSecureStore.ValidateTargetUri(targetUri);
            BaseSecureStore.ValidateCredential(credentials);
        }
    }
}
