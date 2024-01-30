// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Text.Json.Serialization;

namespace IdentityModel.OidcClient.Results
{
    internal class ParResult : Result
    {
        [JsonPropertyName("request_uri")]
        public virtual string RequestUri { get; set; }

        [JsonPropertyName("expires_in")]
        public virtual int ExpiresIn { get; set; }
        public virtual ParState State { get; set; }
    }
}