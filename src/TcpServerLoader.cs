/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: TcpServerLoader.cs 
*
* TcpServerLoader.cs is part of VNLib.WebServer which is part of the larger 
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
using System.Data;
using System.Linq;
using System.Text.Json;
using System.Net.Security;
using System.Text.Json.Serialization;

using VNLib.Utils.Logging;
using VNLib.Utils.Resources;
using VNLib.Net.Http;
using VNLib.Net.Transport.Tcp;
using VNLib.Plugins.Essentials.ServiceStack;

using VNLib.WebServer.Config;
using VNLib.WebServer.Transport;
using VNLib.WebServer.TcpMemoryPool;
using VNLib.WebServer.RuntimeLoading;

namespace VNLib.WebServer
{
    internal sealed class TcpServerLoader(JsonDocument hostConfig, ProcessArguments args, ILogProvider tcpLogger)
    {
        const int CacheQuotaDefault = 0;    //Disable cache quota by default, allows unlimited cache

        private readonly LazyInitializer<TcpConfigJson> _conf = new(() =>
        {
            if(hostConfig.RootElement.TryGetProperty(Entry.TCP_CONF_PROP_NAME, out JsonElement tcpEl))
            {
                return tcpEl.Deserialize<TcpConfigJson>(JsonConfigOptions.SerilaizerOptions)!;
            }

            return new TcpConfigJson();
        });

        /// <summary>
        /// Creates and loads a transport provider for a service group
        /// </summary>
        /// <param name="group"></param>
        /// <returns></returns>
        /// <exception cref="ServerConfigurationException"></exception>
        public ITransportProvider GetProviderForServiceGroup(ServiceGroup group)
        {
            SslServerAuthenticationOptions? sslAuthOptions = null;

            //See if certs are defined
            if (group.Hosts.Where(static h => h.TransportInfo.Certificate != null).Any())
            {
                //If any hosts have ssl enabled, all shared endpoints MUST include a certificate to be bound to the same endpoint
                if (!group.Hosts.All(static h => h.TransportInfo.Certificate != null))
                {
                    throw new ServerConfigurationException("One or more service hosts declared a shared endpoint with SSL enabled but not every host declared an SSL certificate for the shared interface");
                }

                //Build the server auth options for this transport provider
                sslAuthOptions = new HostAwareServerSslOptions(group.Hosts, args.HasArgument("--use-os-ciphers"));
            }

            //Check cli args for inline scheduler
            bool inlineScheduler = args.HasArgument("--inline-scheduler");

            //Check cli args thread count
            string? procCount = args.GetArgument("-t") ?? args.GetArgument("--threads");

            if (!uint.TryParse(procCount, out uint threadCount))
            {
                threadCount = (uint)Environment.ProcessorCount;
            }

            TcpConfigJson basConfig = _conf.Instance;

            //Init a new TCP config
            TCPConfig tcpConf = new()
            {
                AcceptThreads = threadCount,

                CacheQuota = CacheQuotaDefault,
               
                Log = tcpLogger,

                //Service endpoint to listen on
                LocalEndPoint = group.ServiceEndpoint,

                MaxConnections = basConfig.MaxConnections,

                //Copy from base config
                TcpKeepAliveTime = basConfig.TcpKeepAliveTime,
                KeepaliveInterval = basConfig.KeepaliveInterval,
                TcpKeepalive = basConfig.TcpKeepAliveTime > 0,  //Enable keepalive if user specifies a duration
               
                MaxRecvBufferData = basConfig.MaxRecvBufferData,
                BackLog = basConfig.BackLog,
                DebugTcpLog = args.HasArgument("--log-transport"),

                //Init buffer pool
                BufferPool = PoolManager.GetPool(args.ZeroAllocations)
            };

            //Print warning message, since inline scheduler is an avanced feature
            if (sslAuthOptions is not null && inlineScheduler)
            {
                tcpLogger.Debug("[WARN]: Inline scheduler is not available on server {server} when using TLS", group.ServiceEndpoint);
            }

            //Init new tcp server with/without ssl
            return sslAuthOptions != null
                ? TcpTransport.CreateServer(in tcpConf, sslAuthOptions)
                : TcpTransport.CreateServer(in tcpConf, inlineScheduler);

        }

        sealed class TcpConfigJson
        {
            [JsonPropertyName("keepalive_sec")]
            public int TcpKeepAliveTime { get; set; } = 4;

            [JsonPropertyName("keepalive_interval_sec")]
            public int KeepaliveInterval { get; set; } = 4;

            [JsonPropertyName("max_recv_buffer")]
            public int MaxRecvBufferData { get; set; } = 10 * 64 * 1024;

            [JsonPropertyName("backlog")]
            public int BackLog { get; set; } = 1000;

            [JsonPropertyName("max_connections")]
            public long MaxConnections { get; set; } = long.MaxValue;
        }
    }
}
