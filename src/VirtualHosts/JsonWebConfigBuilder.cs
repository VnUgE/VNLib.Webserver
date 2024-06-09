/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: JsonWebConfigBuilder.cs 
*
* JsonWebConfigBuilder.cs is part of VNLib.WebServer which is part of the larger 
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
using System.Data;
using System.Linq;
using System.Text.Json;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;

using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;

using VNLib.WebServer.Config;
using VNLib.WebServer.Config.Model;
using static VNLib.WebServer.Entry;

namespace VNLib.WebServer
{

    internal sealed partial class JsonWebConfigBuilder(JsonElement rootEl, TimeSpan execTimeout, ILogProvider logger) 
        : IVirtualHostConfigBuilder
    {
        //Use pre-compiled default regex
        private static readonly Regex DefaultRootRegex = MyRegex();

        private readonly Dictionary<string, JsonElement> _rootConfig = rootEl.EnumerateObject().ToDictionary(static kv => kv.Name, static kv => kv.Value);
       
        ///<inheritdoc/>
        public VirtualHostConfig GetBaseConfig()
        {
            string? rootDir = _rootConfig[SERVER_ROOT_PATH_PROP_NAME].GetString();

            Validate.EnsureNotNull(rootDir, $"A virtual host was defined without a root directory property: '{SERVER_ROOT_PATH_PROP_NAME}'");

            TransportInterface transport = GetInterface();
            X509Certificate? cert = transport.LoadCertificate();

            //Set cert state for client cert required
            cert?.IsClientCertRequired(transport.ClientCertRequired);

            //Declare the vh config
            VirtualHostConfig vhConfig = new()
            {
                //File root is required
                RootDir = new(rootDir),

                //Set optional whitelist
                WhiteList = GetWhitelist(),

                //Set required downstream servers
                DownStreamServers = GetDownStreamServers(),

                ExcludedExtensions = GetExlcudedExtensions(),
                DefaultFiles = GetDefaultFiles(),
                
                Certificate = cert,

                //Set inerface
                TransportEndpoint = transport.GetEndpoint(),

                PathFilter = GetPathFilter(),

                //Default cache endpoint
                CacheDefault = _rootConfig[SERVER_CACHE_DEFAULT_PROP_NAME].GetTimeSpan(TimeParseType.Seconds),

                //Get the client additionals headers
                AdditionalHeaders = GetConfigHeaders(),

                //Get special headers
                SpecialHeaders = GetSpecialHeaders(),

                //execution timeout
                ExecutionTimeout = execTimeout,

                FailureFiles = GetFailureFiles(),

                LogProvider = logger,
                
                //Hostname is ignored incase its an array of multiple names
            };

            return vhConfig;
        }
    
        public string[] GetHostnames()
        {

            //Allow hostnames element as an array or allow a single hostname property
            string[] hostNames;

            //Try to get the array element first
            if (_rootConfig.TryGetValue(SERVER_HOSTNAME_ARRAY_PROP_NAME, out JsonElement hnArrEl))
            {
                //Get the hostnames array, as a distinct list, to ingnore any repeats
                hostNames = hnArrEl.EnumerateArray()
                                    .Where(static p => p.GetString() != null)
                                    .Select(static p => p.GetString()!)
                                    .Distinct()
                                    .ToArray();
            }
            else if (_rootConfig.TryGetValue(SERVER_HOSTNAME_PROP_NAME, out JsonElement hnEl))
            {
                //Select single hostname
                hostNames =
                [
                    hnEl.GetString() ?? throw new ArgumentException($"A virtual host was defined without a hostname property: '{SERVER_HOSTNAME_PROP_NAME}'")
                ];
            }
            else
            {
                throw new KeyNotFoundException("Missing the hostname or hostnames array elements in virtual host configuration");
            }

            return hostNames;
        }

        private TransportInterface GetInterface()
        {
            if (!_rootConfig.TryGetValue(SERVER_ENDPOINT_PROP_NAME, out JsonElement interfaceEl))
            {
                //Use the default config
                return new();
            }

            TransportInterface? iFace = interfaceEl.DeserializeElement<TransportInterface>();

            Validate.EnsureNotNull(iFace, "The interface configuration is required");

            Validate.EnsureNotNull(iFace.Address, "The interface IP address is required");
            Validate.EnsureValidIp(iFace.Address, "The interface IP address is invalid");
            Validate.Assert(iFace.Port > 0, "The interface port must be greater than 0");
            Validate.Assert(iFace.Port < 65536, "The interface port must be less than 65536");

            return iFace;
        }

        private Regex GetPathFilter()
        {
            //Allow site to define a regex filter pattern
            return _rootConfig.TryGetValue(SERVER_PATH_FILTER_PROP_NAME, out JsonElement rootRegexEl)
                ? new(rootRegexEl.GetString()!)
                : DefaultRootRegex;
        }

        private FrozenDictionary<HttpStatusCode, FileCache> GetFailureFiles()
        {
            //if a failure file array is specified, capure all files and
            if (_rootConfig.TryGetValue(SERVER_ERROR_FILE_PROP_NAME, out JsonElement errEl))
            {
                //Get the error files
                IEnumerable<KeyValuePair<HttpStatusCode, string>> ffs = errEl.EnumerateArray()
                        .Select(static f => new KeyValuePair<HttpStatusCode, string>(
                            (HttpStatusCode)f.GetProperty("code").GetInt32(),
                            f.GetProperty("path").GetString()!
                        ));

                //Create the file cache dictionary
                (HttpStatusCode, string, FileCache?)[] loadCache = ffs.Select(kv =>
                {
                    FileCache? cached = FileCache.Create(kv.Key, kv.Value);
                    return (kv.Key, kv.Value, cached);

                }).ToArray();

                int loadedFiles = loadCache.Where(loadCache => loadCache.Item3 != null)
                    .Count();

                string[] notFoundFiles = loadCache.Where(loadCache => loadCache.Item3 == null)
                    .Select(l => Path.GetFileName(l.Item2))
                    .ToArray();

                if(notFoundFiles.Length > 0)
                {
                    logger.Warn("Failed to load error files {files} for host {hosts}", notFoundFiles, GetHostnames());
                }

                //init frozen dictionary from valid cached files
                return loadCache.Where(kv => kv.Item3 != null)
                    .ToDictionary(kv => kv.Item1, kv => kv.Item3!)
                    .ToFrozenDictionary();
            }

            return new Dictionary<HttpStatusCode, FileCache>().ToFrozenDictionary();
        }

        private FrozenSet<IPAddress> GetDownStreamServers()
        {
            //Find downstream servers
            HashSet<IPAddress>? downstreamServers = null;

            //See if element is set
            if (_rootConfig.TryGetValue(DOWNSTREAM_TRUSTED_SERVERS_PROP, out JsonElement downstreamEl))
            {
                //hash addresses, make is distinct
                downstreamServers = downstreamEl.EnumerateArray()
                    .Select(static addr => IPAddress.Parse(addr.GetString()!))
                    .Distinct()
                    .ToHashSet();
            }

            return (downstreamServers ?? []).ToFrozenSet();
        }

        private FrozenSet<IPAddress>? GetWhitelist()
        {
            //See if whitelist is defined, if so, get a distinct list of arrays
            return _rootConfig.TryGetValue(SERVER_WHITELIST_PROP_NAME, out JsonElement wlEl)
                ? wlEl.EnumerateArray()
                    .Select(static addr => IPAddress.Parse(addr.GetString()!))
                    .Distinct()
                    .ToHashSet()
                    .ToFrozenSet()
                : null;
        }

        private FrozenSet<string> GetExlcudedExtensions()
        {
            //Get exlucded/denied extensions from config
            if (_rootConfig.TryGetValue(SERVER_DENY_EXTENSIONS_PROP_NAME, out JsonElement denyEl))
            {
                //get blocked extensions for the root
                return denyEl.EnumerateArray().Select(static el => el.GetString())
                        .Distinct()
                        .ToHashSet()
                        .ToFrozenSet()!;
            }
            else
            {
                return new HashSet<string>().ToFrozenSet();
            }
        }

        private IReadOnlyCollection<string> GetDefaultFiles()
        {
            //Get blocked extensions for the root
            return _rootConfig.TryGetValue(SERVER_DEFAULT_FILE_PROP_NAME, out JsonElement defFileEl)
                    ? defFileEl.EnumerateArray()
                        .Where(static s => s.GetString() != null)
                        .Select(static s => s.GetString()!)
                        .Distinct()
                        .ToList()
                    : Array.Empty<string>();
        }

        private KeyValuePair<string, string>[] GetConfigHeaders()
        {
            //get the headers array property
            if (!_rootConfig.TryGetValue(SERVER_HEADERS_PROP_NAME, out JsonElement headerEl))
            {
                return [];
            }

            //Enumerate kv headers
            return headerEl.EnumerateObject()
                    //Exclude special headers
                    .Where(static p => !SpecialHeaders.SpecialHeader.Contains(p.Name, StringComparer.OrdinalIgnoreCase))
                    .Select(static p => new KeyValuePair<string, string>(p.Name!, p.Value.GetString()!))
                    .ToArray();
        }

        private FrozenDictionary<string, string> GetSpecialHeaders()
        {
            //get the headers array property
            if (!_rootConfig.TryGetValue(SERVER_HEADERS_PROP_NAME, out JsonElement headerEl))
            {
                return new Dictionary<string, string>().ToFrozenDictionary();
            }

            //Enumerate kv header
            return headerEl.EnumerateObject()
                    //Only include special headers
                    .Where(static p => SpecialHeaders.SpecialHeader.Contains(p.Name, StringComparer.OrdinalIgnoreCase))
                    //Create the special dictionary
                    .ToDictionary(static k => k.Name, static k => k.Value.GetString()!, StringComparer.OrdinalIgnoreCase)
                    .ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
        }


        [GeneratedRegex(@"(\/\.\.)|(\\\.\.)|[\[\]^*<>|`~'\n\r\t\n]|(\s$)|^(\s)", RegexOptions.Compiled)]
        private static partial Regex MyRegex();
    }
}
