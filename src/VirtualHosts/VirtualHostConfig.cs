/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: VirtualHostConfig.cs 
*
* VirtualHostConfig.cs is part of VNLib.WebServer which is part of the larger 
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

using VNLib.Plugins.Essentials;
using VNLib.Plugins.Essentials.ServiceStack;
using VNLib.Plugins.Essentials.ServiceStack.Construction;

namespace VNLib.WebServer
{
    /// <summary>
    /// Implementation of <see cref="IEpProcessingOptions"/>
    /// with <see cref="VirtualHostHooks"/> extra processing options
    /// </summary>
    internal sealed class VirtualHostConfig : VirtualHostConfiguration, IEpProcessingOptions, IHostTransportInfo
    {
        public VirtualHostConfig()
        {
            //Update file attributes
            AllowedAttributes = FileAttributes.Archive | FileAttributes.Compressed | FileAttributes.Normal | FileAttributes.ReadOnly;
            DissallowedAttributes = FileAttributes.Device
                | FileAttributes.Directory
                | FileAttributes.Encrypted
                | FileAttributes.Hidden
                | FileAttributes.IntegrityStream
                | FileAttributes.Offline
                | FileAttributes.ReparsePoint
                | FileAttributes.System;
        }

        /// <summary>
        /// Endables cross origin resoruce sharing protections
        /// </summary>
        public bool? AllowCors { get; init; }

        /// <summary>
        /// A regex filter instance to filter incoming filesystem paths
        /// </summary>
        public Regex? PathFilter { get; init; }
      
        /// <summary>
        /// An optional whitelist set of ipaddresses that are allowed to make connections to this site
        /// </summary>
        public IReadOnlySet<IPAddress>? WhiteList { get; init; }
       
        /// <summary>
        /// The default response entity cache value
        /// </summary>
        public TimeSpan CacheDefault { get; init; }

        /// <summary>
        /// A collection of allowed cors sites, otherwise defaults to the 
        /// connections supplied origin authority
        /// </summary>
        public IReadOnlySet<string>? AllowedCorsAuthority { get; init; }

        /// <summary>
        /// A collection of in-memory files to send in response to processing error
        /// codes.
        /// </summary>
        public IReadOnlyDictionary<HttpStatusCode, FailureFile> FailureFiles { get; init; } = new Dictionary<HttpStatusCode, FailureFile>();

        /// <summary>
        /// Allows config to specify contant additional headers
        /// </summary>
        public IReadOnlyList<KeyValuePair<string, string>> AdditionalHeaders { get; init; } = Array.Empty<KeyValuePair<string, string>>();

        /// <summary>
        /// Contains internal headers used for specific purposes, cherrypicked from the config headers 
        /// </summary>
        public IReadOnlyDictionary<string, string> SpecialHeaders { get; init; } = new Dictionary<string, string>();
    }
}