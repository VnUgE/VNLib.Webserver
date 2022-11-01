using System.Net;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

using VNLib.Utils.Extensions;
using VNLib.Plugins;
using VNLib.Plugins.Runtime;
using VNLib.Plugins.Essentials.Content;
using VNLib.Plugins.Essentials.Sessions;

namespace VNLib.WebServer.RuntimeLoading
{

    /// <summary>
    /// Represents a collection of virtual hosts that share a 
    /// common transport (interface, port, and SSL status)
    /// and may be loaded by a single server instance.
    /// </summary>
    internal class ServiceGroup 
    {
        private readonly LinkedList<VirtualHost> _vHosts;
        private readonly ConditionalWeakTable<WebPluginLoader, IEndpoint[]> _endpointsForPlugins;

        public IPEndPoint ServiceEndpoint { get; }

        public IReadOnlyCollection<VirtualHost> Hosts => _vHosts;

        /// <summary>
        /// Initalizes a new <see cref="ServiceGroup"/> of virtual hosts
        /// with common transport
        /// </summary>
        /// <param name="serviceEndpoint">The <see cref="IPEndPoint"/> to listen for connections on</param>
        /// <param name="hosts">The hosts that share a common interface endpoint</param>
        public ServiceGroup(IPEndPoint serviceEndpoint, IEnumerable<VirtualHost> hosts)
        {
            _endpointsForPlugins = new();
            _vHosts = new(hosts);
            ServiceEndpoint = serviceEndpoint;
        }

        /// <summary>
        /// Sets the specified page rotuer for all virtual hosts
        /// </summary>
        /// <param name="router">The page router to user</param>
        public void UpdatePageRouter(IPageRouter router) => _vHosts.TryForeach(v => v.SetPageRouter(router));
        /// <summary>
        /// Sets the specified session provider for all virtual hosts
        /// </summary>
        /// <param name="current">The session provider to use</param>
        public void UpdateSessionProvider(ISessionProvider current) => _vHosts.TryForeach(v => v.SetSessionProvider(current));

        /// <summary>
        /// Adds or updates all endpoints exported by all plugins
        /// within the specified loader. All endpoints exposed
        /// by a previously loaded instance are removed and all
        /// currently exposed endpoints are added to all virtual 
        /// hosts
        /// </summary>
        /// <param name="loader">The plugin loader to get add/update endpoints from</param>
        public void AddOrUpdateEndpointsForPlugin(WebPluginLoader loader)
        {
            //Get all new endpoints for plugin
            IEndpoint[] newEndpoints = loader.LivePlugins.SelectMany(static pl => pl.Plugin!.GetEndpoints()).ToArray();

            //See if 
            if(_endpointsForPlugins.TryGetValue(loader, out IEndpoint[]? oldEps))
            {
                //Remove old endpoints
                _vHosts.TryForeach(v => v.RemoveEndpoint(oldEps));
            }

            //Add endpoints to dict
            _endpointsForPlugins.AddOrUpdate(loader, newEndpoints);

            //Add endpoints to hosts
            _vHosts.TryForeach(v => v.AddEndpoint(newEndpoints));
        }

        /// <summary>
        /// Unloads all previously stored endpoints, router, session provider, and 
        /// clears all internal data structures
        /// </summary>
        public void UnloadAll()
        {
            //Remove all loaded endpoints
            _vHosts.TryForeach(v => _endpointsForPlugins.TryForeach(eps => v.RemoveEndpoint(eps.Value)));

            //Remove all routers
            _vHosts.TryForeach(static v => v.SetPageRouter(null));
            //Remove all session providers
            _vHosts.TryForeach(static v => v.SetSessionProvider(null));

            //Clear all hosts
            _vHosts.Clear();
            //Clear all endpoints
            _endpointsForPlugins.Clear();
        }
    }
}
