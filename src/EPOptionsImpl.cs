﻿/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: EPOptionsImpl.cs 
*
* EPOptionsImpl.cs is part of VNLib.WebServer which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.WebServer is free software: you can redistribute it and/or modify 
* it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 2 of the License,
* or (at your option) any later version.
*
* VNLib.WebServer is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
* General Public License for more details.
*
* You should have received a copy of the GNU General Public License 
* along with VNLib.WebServer. If not, see http://www.gnu.org/licenses/.
*/

using System;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;

using VNLib.Plugins.Essentials;
using VNLib.Plugins.Essentials.ServiceStack;

namespace VNLib.WebServer
{
    /// <summary>
    /// Implementation of <see cref="IEpProcessingOptions"/>
    /// with <see cref="VirtualHost"/> extra processing options
    /// </summary>
    internal sealed class EPOptionsImpl : IEpProcessingOptions, IHostTransportInfo
    {
        ///<inheritdoc/>
        public FileAttributes AllowedAttributes { get; } = FileAttributes.Archive | FileAttributes.Compressed | FileAttributes.Normal | FileAttributes.ReadOnly;

        ///<inheritdoc/>
        public FileAttributes DissallowedAttributes { get; } = FileAttributes.Device
         | FileAttributes.Directory
         | FileAttributes.Encrypted
         | FileAttributes.Hidden
         | FileAttributes.IntegrityStream
         | FileAttributes.Offline
         | FileAttributes.ReparsePoint
         | FileAttributes.System;

        ///<inheritdoc/>
        public IReadOnlyCollection<string> DefaultFiles { get; set; } = new List<string>();
        ///<inheritdoc/>
        public IReadOnlySet<string> ExcludedExtensions { get; set; } = new HashSet<string>();
        ///<inheritdoc/>
        public IReadOnlySet<IPAddress> DownStreamServers { get; set; } = new HashSet<IPAddress>();
        ///<inheritdoc/>
        public TimeSpan ExecutionTimeout { get; set; } = TimeSpan.FromSeconds(60);


        /// <summary>
        /// Endables cross origin resoruce sharing protections
        /// </summary>
        public bool AllowCors { get; set; }
        /// <summary>
        /// The current sites Content-Secruity-Policy header value
        /// </summary>
        public string? ContentSecurityPolicy { get; set; }
        /// <summary>
        /// The TLS certificate to use for this website
        /// </summary>
        public X509Certificate? Certificate { get; set; }
        /// <summary>
        /// The IP endpoint of the server that should serve this root
        /// </summary>
        public IPEndPoint TransportEndpoint { get; set; } = new(IPAddress.Any, 80);
        /// <summary>
        /// A regex filter instance to filter incoming filesystem paths
        /// </summary>
        public Regex? PathFilter { get; set; }
        /// <summary>
        /// Strict transport security header
        /// </summary>
        public string? HSTSHeader { get; init; }
        /// <summary>
        /// An optional whitelist set of ipaddresses that are allowed to make connections to this site
        /// </summary>
        public IReadOnlySet<IPAddress>? WhiteList { get; init; }
        /// <summary>
        /// Sets the site's referrer policy header
        /// </summary>
        public string? RefererPolicy { get; init; }
        /// <summary>
        /// The default response entity cache value
        /// </summary>
        public TimeSpan CacheDefault { get; init; }

        /// <summary>
        /// A collection of allowed cors sites, otherwise defaults to the 
        /// connections supplied origin authority
        /// </summary>
        public IReadOnlySet<string>? AllowedCorsAuthority { get; init; }
    }
}