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

using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;

using static VNLib.WebServer.Entry;

namespace VNLib.WebServer
{

    internal sealed partial class JsonWebConfigBuilder(JsonElement rootEl, TimeSpan execTimeout, ILogProvider logger, IPEndPoint defaultInterface) : IVirtualHostConfigBuilder
    {
        //Use pre-compiled default regex
        private static readonly Regex DefaultRootRegex = MyRegex();

        private readonly Dictionary<string, JsonElement> _rootConfig = rootEl.EnumerateObject().ToDictionary(static kv => kv.Name, static kv => kv.Value);
       
        ///<inheritdoc/>
        public VirtualHostConfig GetBaseConfig()
        {
            X509Certificate? cert = GetCertificate();

            string rootDir = _rootConfig[SERVER_ROOT_PATH_PROP_NAME].GetString()
                    ?? throw new ArgumentException($"A virtual host was defined without a root directory property: '{SERVER_ROOT_PATH_PROP_NAME}'");


            //Declare the vh config
            VirtualHostConfig vhConfig = new()
            {
                //File root is required
                RootDir = new(rootDir),

                //Cors setup
                AllowCors = GetTriStateCorsEnabled(),
                AllowedCorsAuthority = GetAllowedAuthority(),

                //Set optional whitelist
                WhiteList = GetWhitelist(),

                //Set required downstream servers
                DownStreamServers = GetDownStreamServers(),

                ExcludedExtensions = GetExlcudedExtensions(),
                DefaultFiles = GetDefaultFiles(),

                //store certificate
                Certificate = cert,

                //Set inerface
                TransportEndpoint = GetEndpoint(),

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

            //Set cert state for client cert required
            cert?.IsClientCertRequired(ClientCertRequired());

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

        private IPEndPoint GetEndpoint()
        {
            //Setup a default service interface
            IPEndPoint serverEndpoint = defaultInterface;

            //Get the interface binding for this host
            if (!_rootConfig.TryGetValue(SERVER_ENDPOINT_PROP_NAME, out JsonElement interfaceEl))
            {
                return serverEndpoint;
            }

            //Get the stored IP address
            string ipaddr = interfaceEl.GetProperty(SERVER_ENDPOINT_IP_PROP_NAME).GetString()!;

            IPAddress addr = IPAddress.Parse(ipaddr);

            //Get the port
            int port = interfaceEl.GetProperty(SERVER_ENDPOINT_PORT_PROP_NAME).GetInt32();

            //create the new interface
            serverEndpoint = new(addr, port);

            return serverEndpoint;
        }

        private X509Certificate? GetCertificate()
        {
            //Get ssl object
            if (!_rootConfig.TryGetValue(SERVER_SSL_PROP_NAME, out JsonElement sslConfEl))
            {
                return null;
            }

            //Try to get the cert for the app
            if (!sslConfEl.TryGetProperty(SERVER_CERT_PROP_NAME, out JsonElement certPath))
            {
                return null;
            }

            X509Certificate? cert = null;

            //Get certificate file path
            string certFileName = certPath.GetString()!;

            //If the file is a pem file, load with/without password 
            if (Path.GetExtension(certFileName).EndsWith("pem", StringComparison.OrdinalIgnoreCase))
            {
                //Private key pem file
                string privateKeyFile = sslConfEl.GetPropString(SERVER_PRIV_KEY_PROP_NAME) ?? throw new KeyNotFoundException("You must specify a private key file");

                //try to get a certificate password
                using PrivateString? password = (PrivateString?)sslConfEl.GetPropString("password");

                //Load the cert and decrypt with password if set
                using X509Certificate2 cert2 = password == null ? X509Certificate2.CreateFromPemFile(certFileName, privateKeyFile)
                        : X509Certificate2.CreateFromEncryptedPemFile(certFileName, password.ToReadOnlySpan(), privateKeyFile);

                /*
                 * Workaround for a silly Windows SecureChannel module bug for parsing 
                 * X509Certificate2 from pem cert and private key files. 
                 * 
                 * Must export into pkcs12 format then create a new X509Certificate2 from the 
                 * exported bytes. 
                 */

                //Copy the cert in pkcs12 format
                byte[] pkcs = cert2.Export(X509ContentType.Pkcs12);
                cert = new X509Certificate2(pkcs);
                MemoryUtil.InitializeBlock(pkcs);
            }
            else
            {
                //Create from pfx file including private key
                cert = X509Certificate.CreateFromCertFile(certFileName);
            }

            return cert;
        }

        private bool ClientCertRequired()
        {
            //Get ssl object
            if (!_rootConfig.TryGetValue(SERVER_SSL_PROP_NAME, out JsonElement sslConfEl))
            {
                return false;
            }

            //Try to get the cert for the app
            if (!sslConfEl.TryGetProperty(SERVER_CERT_PROP_NAME, out _))
            {
                return false;
            }

            //Determine if client cert is required
            return sslConfEl.TryGetProperty(SERVER_SSL_CREDS_REQUIRED_PROP_NAME, out JsonElement ccr) && ccr.GetBoolean();
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

        private IReadOnlySet<IPAddress> GetDownStreamServers()
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

            return downstreamServers ?? new();
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

        private FrozenSet<string>? GetAllowedAuthority()
        {
            //Cors authority will be a list of case-insenitive strings we will convert to a hashset
            if (_rootConfig.TryGetValue(SERVER_CORS_AUTHORITY_PROP_NAME, out JsonElement corsAuthEl))
            {
                return corsAuthEl.EnumerateArray()
                            .Where(static v => v.GetString() != null)
                            .Select(static v => v.GetString()!)
                            .Distinct()
                            .ToHashSet(StringComparer.OrdinalIgnoreCase)
                            .ToFrozenSet();
            }

            return null;
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

        private bool? GetTriStateCorsEnabled()
        {
            //If cors is not set, return null
            return _rootConfig.TryGetValue(SERVER_CORS_ENEABLE_PROP_NAME, out JsonElement corsEl) ? corsEl.GetBoolean() : null;
        }



        [GeneratedRegex(@"(\/\.\.)|(\\\.\.)|[\[\]^*<>|`~'\n\r\t\n]|(\s$)|^(\s)", RegexOptions.Compiled)]
        private static partial Regex MyRegex();
    }
}
