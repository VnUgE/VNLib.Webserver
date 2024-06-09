/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: WebserverBase.cs 
*
* WebserverBase.cs is part of VNLib.WebServer which is part of the larger 
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
using System.Text.Json;
using System.Diagnostics;

using VNLib.Net.Http;
using VNLib.Utils;
using VNLib.Plugins.Runtime;
using VNLib.Plugins.Essentials.ServiceStack;
using VNLib.Plugins.Essentials.ServiceStack.Construction;

using VNLib.WebServer.Config;
using VNLib.WebServer.RuntimeLoading;

namespace VNLib.WebServer.Bootstrap
{

    internal abstract class WebserverBase(ServerLogger logger, IServerConfig config, ProcessArguments procArgs) 
        : VnDisposeable
    {

        protected readonly ProcessArguments procArgs = procArgs;
        protected readonly IServerConfig config = config;
        protected readonly ServerLogger logger = logger;
        protected readonly TcpServerLoader TcpConfig = new(config, procArgs, logger.SysLog);

        private HttpServiceStack? _serviceStack;

        /// <summary>
        /// Gets the internal <see cref="HttpServiceStack"/> this 
        /// controller is managing
        /// </summary>
        public HttpServiceStack ServiceStack
        {
            get
            {
                if (_serviceStack is null)
                {
                    throw new InvalidOperationException("Service stack has not been configured yet");
                }

                return _serviceStack;
            }
        }

        /// <summary>
        /// Configures the http server for the application so
        /// its ready to start
        /// </summary>
        public virtual void Configure()
        {
            _serviceStack = ConfiugreServiceStack();
        }

        protected virtual HttpServiceStack ConfiugreServiceStack()
        {
            bool loadPluginsConcurrently = !procArgs.HasArgument("--sequential-load");

            JsonElement conf = config.GetDocumentRoot();

            HttpConfig http = GetHttpConfig();

            PluginStackBuilder? plugins = ConfigurePlugins();

            HttpServiceStackBuilder builder = new HttpServiceStackBuilder()
                                    .LoadPluginsConcurrently(loadPluginsConcurrently)
                                    .WithDomain(LoadRoots)
                                    .WithBuiltInHttp(TcpConfig.GetProviderForServiceGroup, http);

            if (plugins != null)
            {
                builder.WithPluginStack(plugins.ConfigureStack);
            }

            return builder.Build();
        }

        protected abstract void LoadRoots(IDomainBuilder domain);

        protected abstract HttpConfig GetHttpConfig();

        protected abstract PluginStackBuilder? ConfigurePlugins();

        /// <summary>
        /// Starts the server and returns immediately 
        /// after server start listening
        /// </summary>
        public void Start()
        {
            /* Since this api is uses internally, knowing the order of operations is a bug, not a rumtime accident */
            Debug.Assert(Disposed == false, "Server was disposed");
            Debug.Assert(_serviceStack != null, "Server was not configured");

            //Attempt to load plugins before starting server
            _serviceStack.LoadPlugins(logger.AppLog);

            _serviceStack.StartServers();
        }

        /// <summary>
        /// Stops the server and waits for all connections to close and
        /// servers to fully shut down
        /// </summary>
        public void Stop()
        {
            Debug.Assert(Disposed == false, "Server was disposed");
            Debug.Assert(_serviceStack != null, "Server was not configured");

            //Stop the server and wait synchronously
            _serviceStack.StopAndWaitAsync()
                .GetAwaiter()
                .GetResult();
        }

        ///<inheritdoc/>
        protected override void Free() => _serviceStack?.Dispose();
    }
}
