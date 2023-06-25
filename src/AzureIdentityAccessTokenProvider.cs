// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Microsoft.Kiota.Abstractions.Authentication;

namespace Microsoft.Kiota.Authentication.Azure;
/// <summary>
/// Provides an implementation of <see cref="IAccessTokenProvider"/> for Azure.Identity.
/// </summary>
public class AzureIdentityAccessTokenProvider : IAccessTokenProvider, IDisposable
{
    private readonly TokenCredential _credential;
    private readonly ActivitySource _activitySource;
    private readonly HashSet<string> _scopes;
    /// <inheritdoc />
    public AllowedHostsValidator AllowedHostsValidator { get; protected set; }

    /// <summary>
    /// The <see cref="AzureIdentityAccessTokenProvider"/> constructor
    /// </summary>
    /// <param name="credential">The credential implementation to use to obtain the access token.</param>
    /// <param name="allowedHosts">The list of allowed hosts for which to request access tokens.</param>
    /// <param name="scopes">The scopes to request the access token for.</param>
    /// <param name="observabilityOptions">The observability options to use for the authentication provider.</param>
    public AzureIdentityAccessTokenProvider(TokenCredential credential, string []? allowedHosts = null, ObservabilityOptions? observabilityOptions = null, params string[] scopes)
    {
        _credential = credential ?? throw new ArgumentNullException(nameof(credential));

        AllowedHostsValidator = new AllowedHostsValidator(allowedHosts);

        if(scopes == null)
            _scopes = new();
        else
            _scopes = new(scopes, StringComparer.OrdinalIgnoreCase);

        _activitySource = new((observabilityOptions ?? new()).TracerInstrumentationName);
    }

    private const string ClaimsKey = "claims";

    /// <inheritdoc/>
    public async Task<string> GetAuthorizationTokenAsync(Uri uri, Dictionary<string, object>? additionalAuthenticationContext = default, CancellationToken cancellationToken = default)
    {
        using var span = _activitySource?.StartActivity(nameof(GetAuthorizationTokenAsync));
        if(!AllowedHostsValidator.IsUrlHostValid(uri)) {
            span?.SetTag("com.microsoft.kiota.authentication.is_url_valid", false);
            return string.Empty;
        }

        if(!uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)) {
            span?.SetTag("com.microsoft.kiota.authentication.is_url_valid", false);
            throw new ArgumentException("Only https is supported");
        }
        span?.SetTag("com.microsoft.kiota.authentication.is_url_valid", true);

        string? decodedClaim = null;
        if (additionalAuthenticationContext is not null &&
                    additionalAuthenticationContext.ContainsKey(ClaimsKey) &&
                    additionalAuthenticationContext[ClaimsKey] is string claims) {
            span?.SetTag("com.microsoft.kiota.authentication.additional_claims_provided", true);
            var decodedBase64Bytes = Convert.FromBase64String(claims);
            decodedClaim = Encoding.UTF8.GetString(decodedBase64Bytes);
        } else
            span?.SetTag("com.microsoft.kiota.authentication.additional_claims_provided", false);

        string[] scopes;
        if (_scopes.Any()) {
            scopes = _scopes.ToArray();
        } else
            scopes = new string[] { $"{uri.Scheme}://{uri.Host}/.default" };
        span?.SetTag("com.microsoft.kiota.authentication.scopes", string.Join(",", scopes));

        var result = await this._credential.GetTokenAsync(new TokenRequestContext(scopes, claims: decodedClaim), cancellationToken).ConfigureAwait(false);
        return result.Token;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _activitySource?.Dispose();
        GC.SuppressFinalize(this);
    }
}
