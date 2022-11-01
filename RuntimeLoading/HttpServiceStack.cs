using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

using VNLib.Utils;
using VNLib.Net.Http;

namespace VNLib.WebServer.RuntimeLoading
{
    /// <summary>
    /// The service domain controller that manages all 
    /// servers for an application based on a 
    /// <see cref="RuntimeLoading.ServiceDomain"/>
    /// </summary>
    internal sealed class HttpServiceStack : VnDisposeable
    {
        private readonly LinkedList<HttpServer> _servers;

        private CancellationTokenSource? _cts;
        private Task WaitForAllTask;

        /// <summary>
        /// Gets the underlying <see cref="RuntimeLoading.ServiceDomain"/>
        /// </summary>
        public ServiceDomain ServiceDomain { get; }

        /// <summary>
        /// A collection of all loaded servers
        /// </summary>
        public IReadOnlyCollection<HttpServer> Servers => _servers;

        /// <summary>
        /// Initializes a new <see cref="HttpServiceStack"/> that will 
        /// generate servers to listen for services exposed by the 
        /// specified host context
        /// </summary>
        /// <param name="hostManager">The manager that exposes services to listen for</param>
        public HttpServiceStack()
        {
            ServiceDomain = new();
            _servers = new();
            WaitForAllTask = Task.CompletedTask;
        }

        /// <summary>
        /// Builds all http servers from 
        /// </summary>
        /// <param name="config">The http server configuration to user for servers</param>
        /// <param name="getTransports">A callback method that gets the transport provider for the given host group</param>
        public void BuildServers(in HttpConfig config, Func<ServiceGroup, ITransportProvider> getTransports)
        {
            //enumerate hosts groups
            foreach(ServiceGroup hosts in ServiceDomain.ServiceGroups)
            {
                //get transport for provider
                ITransportProvider transport = getTransports.Invoke(hosts);

                //Create new server
                HttpServer server = new(config, transport, hosts.Hosts);

                //Add server to internal list
                _servers.AddLast(server);
            }
        }

        /// <summary>
        /// Starts all configured servers that observe a cancellation
        /// token to cancel
        /// </summary>
        /// <param name="parentToken">The token to observe which may stop servers and cleanup the provider</param>
        public void StartServers(CancellationToken parentToken = default)
        {
            Check();

            //Init new linked cts to stop all servers if cancelled
            _cts = CancellationTokenSource.CreateLinkedTokenSource(parentToken);

            LinkedList<Task> runners = new();

            foreach(HttpServer server in _servers)
            {
                //Start servers and add run task to list
                Task run = server.Start(_cts.Token);
                runners.AddLast(run);
            }

            //Task that waits for all to exit then cleans up
            WaitForAllTask = Task.WhenAll(runners)
                .ContinueWith(OnAllServerExit, CancellationToken.None);
        }

        /// <summary>
        /// Stops listening on all configured servers
        /// and returns a task that completes when the service 
        /// host has stopped all servers and unloaded resources
        /// </summary>
        /// <returns>The task that completes when</returns>
        public Task StopAndWaitAsync()
        {
            _cts?.Cancel();
            return WaitForAllTask;
        }

        private void OnAllServerExit(Task allExit)
        {
            //Unload the hosts
            ServiceDomain.UnloadAll();
        }

        protected override void Free()
        {
            _cts?.Dispose();
           
            ServiceDomain.Dispose();
            
            //remove all lists
            _servers.Clear();
        }
    }
}
