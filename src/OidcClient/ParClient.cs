// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Client;
using IdentityModel.OidcClient.Infrastructure;
using IdentityModel.OidcClient.Results;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityModel.OidcClient
{
    internal class ParClient
    {
        private readonly CryptoHelper _crypto;
        private readonly ILogger<ParClient> _logger;
        private readonly OidcClientOptions _options;

        /// <summary>
        /// Initializes a new instance of the <see cref="ParClient"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        public ParClient(OidcClientOptions options)
        {
            _options = options;
            _logger = options.LoggerFactory.CreateLogger<ParClient>();
            _crypto = new CryptoHelper(options);
        }

        public async Task<ParResult> ParAuthorizeAsync(AuthorizeRequest request,
            CancellationToken cancellationToken = default)
        {
            _logger.LogTrace("ParAuthorizeAsync");

            if (_options.Browser == null)
            {
                throw new InvalidOperationException("No browser configured.");
            }

            ParResult result = new ParResult
            {
                State = CreateParState(request.ExtraParameters)
            };

            var client = _options.CreateClient();
            
            var response = await client.PostAsync(result.State.StartUrl, new FormUrlEncodedContent(result.State.Parameters), cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                result.Error = await response.Content.ReadAsStringAsync();
                return result;
            }

            var parResponse = await JsonSerializer.DeserializeAsync<ParResult>(await response.Content.ReadAsStreamAsync(), cancellationToken: cancellationToken);

            result.RequestUri = parResponse.RequestUri;
            result.ExpiresIn = parResponse.ExpiresIn;

            return result;
        }

        public ParState CreateParState(Parameters frontChannelParameters)
        {
            _logger.LogTrace("CreateParState");

            var pkce = _crypto.CreatePkceData();

            var state = new ParState
            {
                State = _crypto.CreateState(_options.StateLength),
                RedirectUri = _options.RedirectUri,
                CodeVerifier = pkce.CodeVerifier,
            };

            var s = CreateParUrlAndState(state.State, pkce.CodeChallenge, frontChannelParameters);

            state.StartUrl = s.url;
            state.Parameters = s.parameters;

            _logger.LogDebug(LogSerializer.Serialize(state));

            return state;
        }

        internal (string url, Parameters parameters) CreateParUrlAndState(string state, string codeChallenge,
            Parameters frontChannelParameters)
        {
            _logger.LogTrace("CreateParUrlAndState");

            var parameters = CreateParAuthorizeParameters(state, codeChallenge, frontChannelParameters);
            var request = new RequestUrl(_options.ProviderInformation.ParEndpoint);

            return (request.Create(new Parameters()), parameters);
        }

        internal string CreateEndSessionUrl(string endpoint, LogoutRequest request)
        {
            _logger.LogTrace("CreateEndSessionUrl");

            return new RequestUrl(endpoint).CreateEndSessionUrl(
                idTokenHint: request.IdTokenHint,
                postLogoutRedirectUri: _options.PostLogoutRedirectUri,
                state: request.State);
        }

        internal Parameters CreateParAuthorizeParameters(
            string state,
            string codeChallenge,
            Parameters frontChannelParameters)
        {
            _logger.LogTrace("CreateParAuthorizeParameters");

            var parameters = new Parameters
            {
                { OidcConstants.AuthorizeRequest.ResponseType, OidcConstants.ResponseTypes.Code },
                { OidcConstants.AuthorizeRequest.State, state },
                { OidcConstants.AuthorizeRequest.CodeChallenge, codeChallenge },
                { OidcConstants.AuthorizeRequest.CodeChallengeMethod, OidcConstants.CodeChallengeMethods.Sha256 },
            };

            if (_options.ClientId.IsPresent())
            {
                parameters.Add(OidcConstants.AuthorizeRequest.ClientId, _options.ClientId);
            }

            if (_options.ClientSecret.IsPresent())
            {
                parameters.Add("client_secret", _options.ClientSecret);
            }

            if (_options.Scope.IsPresent())
            {
                parameters.Add(OidcConstants.AuthorizeRequest.Scope, _options.Scope);
            }

            if (_options.Resource.Any())
            {
                foreach (var resource in _options.Resource)
                {
                    parameters.Add(OidcConstants.AuthorizeRequest.Resource, resource);
                }
            }

            if (_options.RedirectUri.IsPresent())
            {
                parameters.Add(OidcConstants.AuthorizeRequest.RedirectUri, _options.RedirectUri);
            }

            if (frontChannelParameters != null)
            {
                foreach (var entry in frontChannelParameters)
                {
                    parameters.Add(entry.Key, entry.Value);
                }
            }

            return parameters;
        }
    }
}