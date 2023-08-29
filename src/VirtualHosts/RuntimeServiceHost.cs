/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: RuntimeServiceHost.cs 
*
* RuntimeServiceHost.cs is part of VNLib.WebServer which is part of the larger 
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

using VNLib.Net.Http;
using VNLib.Utils.Logging;
using VNLib.Plugins;
using VNLib.Plugins.Essentials.Content;
using VNLib.Plugins.Essentials.Sessions;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Middleware;
using VNLib.Plugins.Essentials.ServiceStack;

namespace VNLib.WebServer
{
    sealed class RuntimeServiceHost : IServiceHost
    {
        private readonly VirtualHost _host;

        public RuntimeServiceHost(string hostName, ILogProvider log, VirtualHostConfig config)
        {
            //Init new virtual host
            _host = new(hostName, log, config);
        }

        ///<inheritdoc/>
        public IWebRoot Processor => _host;

        ///<inheritdoc/>
        public IHostTransportInfo TransportInfo => _host.VirtualHostOptions;


        void IServiceHost.OnRuntimeServiceAttach(IManagedPlugin plugin, IEndpoint[] endpoints)
        {
            //Configure session provider
            UpdateSessionProvider(plugin);
            UpdatePageRouter(plugin);
            UpdateSecurityProvider(plugin);
            UpdateMiddleware(plugin);

            //Add endpoints to service
            _host.EndpointTable.AddEndpoint(endpoints);
        }

        void IServiceHost.OnRuntimeServiceDetach(IManagedPlugin plugin, IEndpoint[] endpoints)
        {
            //Remove endpoints
            _host.EndpointTable.RemoveEndpoint(endpoints);
        }

        private void UpdateSessionProvider(IManagedPlugin plugin)
        {
            static void OnSessionUnload(RuntimeServiceHost? state)
            {
                //Clear session provider on unload
                state?._host.SetSessionProvider(null);
            }

            //Try to get the session provider 
            object? sess = plugin.TryRegsiterForService(typeof(ISessionProvider), OnSessionUnload, this);

            if (sess != null)
            {
                //Configure session provider
                _host.SetSessionProvider((ISessionProvider)sess);
            }
        }

        private void UpdatePageRouter(IManagedPlugin plugin)
        {
            static void OnRouterUnload(RuntimeServiceHost? state)
            {
                //Clear session provider on unload
                state?._host.SetPageRouter(null);
            }

            //Try to get the session provider 
            object? sess = plugin.TryRegsiterForService(typeof(IPageRouter), OnRouterUnload, this);

            if (sess != null)
            {
                //Configure session provider
                _host.SetPageRouter((IPageRouter)sess);
            }
        }

        private void UpdateSecurityProvider(IManagedPlugin plugin)
        {
            static void OnSecProviderUnload(RuntimeServiceHost? state)
            {
                //Clear session provider on unload
                state?._host.SetSecurityProvider(null);
            }

            //Try to get the session provider 
            object? sess = plugin.TryRegsiterForService(typeof(IAccountSecurityProvider), OnSecProviderUnload, this);

            if (sess != null)
            {
                //Configure session provider
                _host.SetSecurityProvider((IAccountSecurityProvider)sess);
            }
        }

        private void UpdateMiddleware(IManagedPlugin plugin)
        {
            static void OnMiddlewareUnloaded(RuntimeServiceHost? state, object service)
            {
                IHttpMiddleware[] mwList = (IHttpMiddleware[])service;

                //remove all middleware elements
                Array.ForEach(mwList, mw => state?._host.MiddlewareChain.RemoveMiddleware(mw));
            }

            //Try to get the middleware provider
            IHttpMiddleware[]? mw = (IHttpMiddleware[]?)plugin.TryRegsiterForService(typeof(IHttpMiddleware[]), OnMiddlewareUnloaded, this);

            if (mw != null)
            {
                //Add all middleware elements
                Array.ForEach(mw, m => _host.MiddlewareChain.AddLast(m));
            }
        }
    }
}