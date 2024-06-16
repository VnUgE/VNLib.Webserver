/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: ReleaseWebserver.cs 
*
* ReleaseWebserver.cs is part of VNLib.WebServer which is part of the larger 
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
using System.Net;
using System.Data;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Collections.Generic;

using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Net.Http;
using VNLib.Plugins.Runtime;
using VNLib.Plugins.Essentials.ServiceStack.Construction;

using VNLib.WebServer.Config;
using VNLib.WebServer.Config.Model;
using VNLib.WebServer.Plugins;
using VNLib.WebServer.Compression;
using VNLib.WebServer.Middlewares;
using VNLib.WebServer.TcpMemoryPool;
using VNLib.WebServer.RuntimeLoading;
using static VNLib.WebServer.Entry;

namespace VNLib.WebServer.Bootstrap
{

    /*
     * This class represents a normally loaded "Relase" webserver to allow 
     * for module webserver use-cases. It relies on a system configuration
     * file and command line arguments to configure the server.
     */

    internal class ReleaseWebserver(ServerLogger logger, IServerConfig config, ProcessArguments procArgs)
        : WebserverBase(logger, config, procArgs)
    {
        const string FOUND_VH_TEMPLATE =
@"
--------------------------------------------------
 |           Found virtual host:
 | Hostnames: {hn}
 | Directory: {dir}
 | Interface: {ep}
 | Trace connections: {tc}
 | SSL: {ssl}, Client cert required: {cc}
 | Whitelist entries: {wl}
 | Downstream servers: {ds}
 | CORS Enabled: {enlb}
 | Allowed CORS sites: {cors}
 | Cached error files: {ef}
--------------------------------------------------";

        const string PLUGIN_DATA_TEMPLATE =
@"
----------------------------------
 |      Plugin configuration:
 | Enabled: {enabled}
 | Directories: {dir}
 | Hot Reload: {hr}
 | Reload Delay: {delay}s
----------------------------------";

        private readonly ProcessArguments args = procArgs;

        ///<inheritdoc/>
        protected override PluginStackBuilder? ConfigurePlugins()
        {
            //do not load plugins if disabled
            if (args.HasArgument("--no-plugins"))
            {
                logger.AppLog.Information("Plugin loading disabled via options flag");
                return null;
            }

            JsonElement confEl = config.GetDocumentRoot();           

            if (!confEl.TryGetProperty(PLUGINS_CONFIG_PROP_NAME, out JsonElement plCfg))
            {
                logger.AppLog.Debug("No plugin configuration found");
                return null;
            }

            ServerPluginConfig? conf = plCfg.DeserializeElement<ServerPluginConfig>();
            Validate.EnsureNotNull(conf, "Your plugin configuration object is null or malformatted");

            if (!conf.Enabled)
            {
                logger.AppLog.Information("Plugin loading disabled via config");
                return null;
            }

            Validate.EnsureNotNull(conf.Paths, "If plugins are enabled, you must specify a directory to load them from");

            conf.Paths = conf.Paths.Where(static p => !string.IsNullOrWhiteSpace(p)).ToArray();

            //Init new plugin stack builder
            PluginStackBuilder pluginBuilder = PluginStackBuilder.Create()
                                    .WithDebugLog(logger.AppLog)
                                    .WithSearchDirectories(conf.Paths)
                                    .WithLoaderFactory(PluginAsemblyLoading.Create);

            //Setup plugin config data
            if (!string.IsNullOrWhiteSpace(conf.ConfigDir))
            {
                pluginBuilder.WithJsonConfigDir(confEl, new(conf.ConfigDir));
            }
            else
            {
                pluginBuilder.WithLocalJsonConfig(confEl);
            }
            
            if (conf.HotReload)
            {
                Validate.EnsureRange(conf.ReloadDelaySec, 1, 60);

                pluginBuilder.EnableHotReload(TimeSpan.FromSeconds(conf.ReloadDelaySec));
            }

            logger.AppLog.Information(
                PLUGIN_DATA_TEMPLATE,
                true,
                conf.Paths,
                conf.HotReload,
                conf.ReloadDelaySec
            );
           
            return pluginBuilder;
        }
       

        ///<inheritdoc/>
        protected override HttpConfig GetHttpConfig()
        {
            JsonElement rootEl = config.GetDocumentRoot();

            try
            {
                HttpGlobalConfig? gConf = rootEl.GetProperty("http").DeserializeElement<HttpGlobalConfig>();
                Validate.EnsureNotNull(gConf, "Missing required HTTP configuration variables");

                gConf.ValidateConfig();

                //Attempt to load the compressor manager, if null, compression is disabled
                IHttpCompressorManager? compressorManager = HttpCompressor.LoadOrDefaultCompressor(procArgs, gConf.Compression, config, logger.AppLog);

                IHttpMemoryPool memPool = PoolManager.GetHttpPool(procArgs.ZeroAllocations);

                HttpConfig conf = new(logger.SysLog, memPool, Encoding.ASCII)
                {
                    ActiveConnectionRecvTimeout     = gConf.RecvTimeoutMs,
                    CompressorManager               = compressorManager,
                    ConnectionKeepAlive             = TimeSpan.FromMilliseconds(gConf.KeepAliveMs),
                    CompressionLimit                = gConf.Compression.CompressionMax,                    
                    CompressionMinimum              = gConf.Compression.CompressionMin,
                    DebugPerformanceCounters        = procArgs.HasArgument("--http-counters"),
                    DefaultHttpVersion              = HttpHelpers.ParseHttpVersion(gConf.DefaultHttpVersion),
                    MaxFormDataUploadSize           = gConf.MultipartMaxSize,
                    MaxUploadSize                   = gConf.MaxEntitySize,
                    MaxRequestHeaderCount           = gConf.MaxRequestHeaderCount,                    
                    MaxOpenConnections              = gConf.MaxConnections,                    
                    MaxUploadsPerRequest            = gConf.MaxUploadsPerRequest,
                    SendTimeout                     = gConf.SendTimeoutMs,

                    RequestDebugLog                 = procArgs.LogHttp ? logger.AppLog : null,

                    //Buffer config update
                    BufferConfig = new()
                    {
                        RequestHeaderBufferSize = gConf.HeaderBufSize,
                        ResponseHeaderBufferSize = gConf.ResponseHeaderBufSize,
                        FormDataBufferSize = gConf.MultipartMaxBufSize,

                        //Align response buffer size with transport buffer to avoid excessive copy
                        ResponseBufferSize = TcpConfig.TcpTxBufferSize, 

                        /*
                         * Chunk buffers are written to the transport when they are fully accumulated. These buffers
                         * should be aligned with the transport sizes. It should also be large enough not to put too much
                         * back pressure on compressors. This buffer will be segmented into smaller buffers if it has to
                         * at the transport level, but we should avoid that if possible due to multiple allocations and 
                         * copies.
                         * 
                         * Aligning chunk buffer to the transport buffer size is the easiest solution to avoid excessive
                         * copyies
                         */
                        ChunkedResponseAccumulatorSize = compressorManager != null ? TcpConfig.TcpTxBufferSize : 0
                    },
                   
                };

                Validate.Assert(
                    condition: conf.DefaultHttpVersion != Net.Http.HttpVersion.None,
                    message: "Your default HTTP version is invalid, specify an RFC formatted http version 'HTTP/x.x'"
                );

                return conf;
            }
            catch (KeyNotFoundException kne)
            {
                logger.AppLog.Error("Missing required HTTP configuration variables {var}", kne.Message);
                throw new ServerConfigurationException("Missing required http variables. Cannot continue");
            }
        }

        protected override void LoadRoots(IDomainBuilder domain)
        {
            JsonElement rootEl = config.GetDocumentRoot();
            ILogProvider log = logger.AppLog;

            try
            {
                //execution timeout
                TimeSpan execTimeout = rootEl.GetProperty(SESSION_TIMEOUT_PROP_NAME).GetTimeSpan(TimeParseType.Milliseconds);

                if(!rootEl.TryGetProperty("virtual_hosts", out _))
                {
                    log.Warn("No virtual hosts array was defined. Continuing without hosts");
                    return;
                }

                int index = 0;

                //Enumerate all virtual host configurations
                foreach (JsonElement vhElement in rootEl.GetProperty("virtual_hosts").EnumerateArray())
                {
                    //Inint config builder
                    JsonWebConfigBuilder builder = new (index, vhElement, execTimeout, log);

                    //Load the base configuration and hostname list
                    VirtualHostConfig conf = builder.GetBaseConfig();
                    string[] hostnames = builder.GetHostnames();

                    //Configure event hooks
                    conf.EventHooks = new VirtualHostHooks(conf);

                    //Init middleware stack
                    conf.CustomMiddleware.Add(new MainServerMiddlware(log, conf, builder.VhConfig.ForcePortCheck));

                    /*
                     * In benchmark mode, skip other middleware that might slow connections down
                     */
                    if (builder.VhConfig.Benchmark?.Enabled == true)
                    {
                        conf.CustomMiddleware.Add(new BenchmarkMiddleware(builder.VhConfig.Benchmark));
                        log.Information("BENCHMARK: Enabled for virtual host {vh}", conf.Hostname);
                    }
                    else
                    {
                        /*
                         * We only enable cors if the configuration has a value for the allow cors property.
                         * The user may disable cors totally, deny cors requests, or enable cors with a whitelist
                         * 
                         * Only add the middleware if the confg has a value for the allow cors property
                         */
                        if (builder.VhConfig.Cors?.Enabled == true)
                        {
                            conf.CustomMiddleware.Add(new CORSMiddleware(log, builder.VhConfig.Cors));
                        }

                        //Add whitelist middleware if the configuration has a whitelist
                        if (conf.WhiteList != null)
                        {
                            conf.CustomMiddleware.Add(new WhitelistMiddleware(log, conf.WhiteList));
                        }

                        //Add tracing middleware if enabled
                        if (builder.VhConfig.RequestTrace)
                        {
                            conf.CustomMiddleware.Add(new ConnectionLogMiddleware(log));
                        }
                    }

                    if (!conf.RootDir.Exists)
                    {
                        conf.RootDir.Create();
                    }

                    //Get all virtual hosts configurations and add them to the domain
                    foreach (string hostname in hostnames)
                    {
                        VirtualHostConfig clone = conf.Clone();
                        clone.Hostname = hostname.Replace(LOAD_DEFAULT_HOSTNAME_VALUE, Dns.GetHostName(), StringComparison.OrdinalIgnoreCase);
                        //Add each config with new hostname to the domain
                        domain.WithVirtualHost(clone);
                    }

                    //print found host to log
                    {
                        //Log the 
                        log.Information(
                            FOUND_VH_TEMPLATE,
                            hostnames,
                            conf.RootDir.FullName,
                            conf.TransportEndpoint,
                            builder.VhConfig.RequestTrace,
                            conf.Certificate != null,
                            conf.Certificate.IsClientCertRequired(),
                            conf.WhiteList?.ToArray(),
                            conf.DownStreamServers?.ToArray(),
                            builder.VhConfig.Cors?.Enabled == true,
                            builder.VhConfig.Cors?.AllowedCorsAuthority,
                            conf.FailureFiles.Select(p => (int)p.Key).ToArray()
                        );
                    }

                    index++;
                }
            }
            catch (KeyNotFoundException kne)
            {
                throw new ServerConfigurationException("Missing required configuration varaibles", kne);
            }
            catch (FormatException fe)
            {
                throw new ServerConfigurationException("Failed to parse IP address", fe);
            }
        }
    }
}
