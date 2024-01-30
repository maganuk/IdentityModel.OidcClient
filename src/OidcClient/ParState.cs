// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;

namespace IdentityModel.OidcClient
{
    /// <summary>
    /// Represents the state the needs to be hold between starting the authorize request and the response
    /// </summary>
    public class ParState : AuthorizeState
    {
        /// <summary>
        /// Gets or sets the request parameters.
        /// </summary>
        /// <value>
        /// The request parameters.
        /// </value>
        public Parameters Parameters { get; set; }
    }
}