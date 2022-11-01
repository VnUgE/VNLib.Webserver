using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;

using VNLib.Plugins;

using VNLib.Utils;
using VNLib.Utils.IO;
using VNLib.Utils.Extensions;
using VNLib.Utils.Logging;
using VNLib.Plugins.Runtime;
using VNLib.Plugins.Essentials.Content;
using VNLib.Plugins.Essentials.Sessions;

namespace VNLib.WebServer.RuntimeLoading
{
    /// <summary>
    /// Represents a domain of services and thier dynamically loaded plugins 
    /// that will be hosted by an application service stack
    /// </summary>
    internal sealed class ServiceDomain : VnDisposeable
    {
        private const string PLUGIN_FILE_EXTENSION = ".dll";
        private const string DEFUALT_PLUGIN_DIR = "/plugins";
        private const string PLUGINS_CONFIG_ELEMENT = "plugins";

        private readonly LinkedList<ServiceGroup> _serviceGroups;
        private readonly LinkedList<WebPluginLoader> _pluginLoaders;
        
        /// <summary>
        /// Enumerates all loaded plugin instances
        /// </summary>
        public IEnumerable<IPlugin> Plugins => _pluginLoaders.SelectMany(static s => s.LivePlugins.Where(static p => p.Plugin != null).Select(static s => s.Plugin!));

        /// <summary>
        /// Gets all service groups loaded in the service manager
        /// </summary>
        public IReadOnlyCollection<ServiceGroup> ServiceGroups => _serviceGroups;

        /// <summary>
        /// Initializes a new empty <see cref="ServiceDomain"/>
        /// </summary>
        public ServiceDomain()
        {
            _serviceGroups = new();
            _pluginLoaders = new();
        }

        /// <summary>
        /// Uses the supplied callback to get a collection of virtual hosts
        /// to build the current domain with
        /// </summary>
        /// <param name="hostBuilder">The callback method to build virtual hosts</param>
        /// <returns>A value that indicates if any virtual hosts were successfully loaded</returns>
        public bool BuildDomain(Action<ICollection<VirtualHost>> hostBuilder)
        {
            //LL to store created hosts
            LinkedList<VirtualHost> hosts = new();

            //build hosts
            hostBuilder.Invoke(hosts);

            return FromExisting(hosts);
        }

        /// <summary>
        /// Builds the domain from an existing enumeration of virtual hosts
        /// </summary>
        /// <param name="hosts">The enumeration of virtual hosts</param>
        /// <returns>A value that indicates if any virtual hosts were successfully loaded</returns>
        public bool FromExisting(IEnumerable<VirtualHost> hosts)
        {
            //Get service groups and pass service group list
            CreateServiceGroups(_serviceGroups, hosts);
            return _serviceGroups.Any();
        }
       
        private static void CreateServiceGroups(ICollection<ServiceGroup> groups, IEnumerable<VirtualHost> hosts)
        {
            //Get distinct interfaces
            IEnumerable<IPEndPoint> interfaces = hosts.Select(static s => s.ServerEndpoint).Distinct();

            //Select hosts of the same interface to create a group from
            foreach (IPEndPoint iface in interfaces)
            {
                IEnumerable<VirtualHost> groupHosts = hosts.Where(host => host.ServerEndpoint.Equals(iface));
                //init new service group around an interface and its roots
                ServiceGroup group = new(iface, groupHosts);

                groups.Add(group);
            }
        }

        /// <summary>
        /// Loads all plugins specified by the host config to the service manager,
        /// or attempts to load plugins by the default
        /// </summary>
        /// <param name="config">The configuration instance to pass to plugins</param>
        /// <param name="appLog">A log provider to write message and errors to</param>
        /// <returns>A task that resolves when all plugins are loaded</returns>
        public Task LoadPluginsAsync(JsonDocument config, ILogProvider appLog) => Task.Run(() => LoadPluginsInternal(config, appLog));

        private async Task LoadPluginsInternal(JsonDocument config, ILogProvider appLog)
        {
            if (!config.RootElement.TryGetProperty(PLUGINS_CONFIG_ELEMENT, out JsonElement pluginEl))
            {
                appLog.Information("Plugins element not defined in config, skipping plugin loading");
                return;
            }

            //Get the plugin directory, or set to default
            string pluginDir = pluginEl.GetPropString("path") ?? Path.Combine(Directory.GetCurrentDirectory(), DEFUALT_PLUGIN_DIR);
            //Get the hot reload flag
            bool hotReload = pluginEl.TryGetProperty("hot_reload", out JsonElement hrel) && hrel.GetBoolean();

            //Load all virtual file assemblies withing the plugin folder
            DirectoryInfo dir = new(pluginDir);

            if (!dir.Exists)
            {
                appLog.Warn("Plugin directory {dir} does not exist. No plugins were loaded", pluginDir);
                return;
            }

            appLog.Debug("Loading plugins. Hot-reload enabled {en}", hotReload);

            //Enumerate all dll files within this dir
            IEnumerable<DirectoryInfo> dirs = dir.EnumerateDirectories("*", SearchOption.TopDirectoryOnly);

            //Select only dirs with a dll that is named after the directory name
            IEnumerable<string> pluginPaths = dirs.Where(static pdir =>
            {
                string compined = Path.Combine(pdir.FullName, pdir.Name);
                string FilePath = string.Concat(compined, PLUGIN_FILE_EXTENSION);
                return FileOperations.FileExists(FilePath);
            })
            //Return the name of the dll file to import
            .Select(static pdir =>
            {
                string compined = Path.Combine(pdir.FullName, pdir.Name);
                return string.Concat(compined, PLUGIN_FILE_EXTENSION);
            });

            appLog.Debug("Found plugin files: \n{files}", (object)pluginPaths.ToArray());

            List<Task> loading = new();

            foreach (string pluginPath in pluginPaths)
            {
                async Task Load()
                {
                    WebPluginLoader plugin = new(pluginPath, config, appLog, hotReload, hotReload);
                    try
                    {
                        await plugin.InitLoaderAsync();
                        //Listen for reload events to remove and re-add endpoints
                        plugin.Reloaded += OnPluginReloaded;
                        //Add to list
                        _pluginLoaders.AddLast(plugin);
                    }
                    catch (Exception ex)
                    {
                        appLog.Error(ex);
                        plugin.Dispose();
                    }
                }

                loading.Add(Load());
            }

            appLog.Verbose("Waiting for enabled plugins to load");

            //wait for loading to completed
            await Task.WhenAll(loading.ToArray());

            appLog.Verbose("Plugins loaded");

            //Add inital endpoints for all plugins
            _pluginLoaders.TryForeach(ldr => _serviceGroups.TryForeach(sg => sg.AddOrUpdateEndpointsForPlugin(ldr)));

            //Init session provider
            InitSessionProvider();

            //Init page router
            InitPageRouter();
        }

        /// <summary>
        /// Sends a message to a plugin identified by it's name.
        /// </summary>
        /// <param name="pluginName">The name of the plugin to pass the message to</param>
        /// <param name="message">The message to pass to the plugin</param>
        /// <param name="nameComparison">The name string comparison type</param>
        /// <returns>True if the plugin was found and it has a message handler loaded</returns>
        /// <exception cref="ObjectDisposedException"></exception>
        public bool SendCommandToPlugin(string pluginName, string message, StringComparison nameComparison = StringComparison.Ordinal)
        {
            Check();
            //Find the single plugin by its name
            LivePlugin? pl = _pluginLoaders.Select(p =>
                                    p.LivePlugins.Where(lp => pluginName.Equals(lp.PluginName, nameComparison))
                                )
                            .SelectMany(static lp => lp)
                            .SingleOrDefault();
            //Send the command
            return pl?.SendConsoleMessage(message) ?? false;
        }

        /// <summary>
        /// Manually reloads all plugins loaded to the current service manager
        /// </summary>
        /// <exception cref="AggregateException"></exception>
        /// <exception cref="ObjectDisposedException"></exception>
        public void ForceReloadAllPlugins()
        {
            Check();
            _pluginLoaders.TryForeach(static pl => pl.ReloadPlugin());
        }

        /// <summary>
        /// Unloads all service groups, removes them, and unloads all
        /// loaded plugins
        /// </summary>
        /// <exception cref="AggregateException"></exception>
        /// <exception cref="ObjectDisposedException"></exception>
        public void UnloadAll()
        {
            Check();

            //Unload service groups before unloading plugins
            _serviceGroups.TryForeach(static sg => sg.UnloadAll());
            //empty service groups
            _serviceGroups.Clear();

            //Unload all plugins
            _pluginLoaders.TryForeach(static pl => pl.UnloadAll());

            //Dispose instance
            Dispose(true);
        }

        private void OnPluginReloaded(object? plugin, EventArgs empty)
        {
            //Update endpoints for the loader
            WebPluginLoader reloaded = (plugin as WebPluginLoader)!;

            //Update all endpoints for the plugin
            _serviceGroups.TryForeach(sg => sg.AddOrUpdateEndpointsForPlugin(reloaded));
        }

        private void InitSessionProvider()
        {

            //Callback to reload provider
            void onSessionProviderReloaded(ISessionProvider old, ISessionProvider current)
            {
                _serviceGroups.TryForeach(sg => sg.UpdateSessionProvider(current));
            }

            try
            {
                //get the loader that contains the single session provider
                WebPluginLoader? sessionLoader = _pluginLoaders
                    .Where(static s => s.ExposesType<IServiceProvider>())
                    .SingleOrDefault();

                //If session provider has been supplied, load it
                if (sessionLoader != null)
                {
                    //Get the session provider from the plugin loader
                    ISessionProvider sp = (sessionLoader.GetLoaderForSingleType<ISessionProvider>()!.Plugin as ISessionProvider)!;

                    //Init inital provider
                    onSessionProviderReloaded(null!, sp);

                    //Register reload event
                    sessionLoader.RegisterListenerForSingle<ISessionProvider>(onSessionProviderReloaded);
                }
            }
            catch (InvalidOperationException)
            {
                throw new TypeLoadException("More than one page router plugin was defined in the plugin directory, cannot continue");
            }
        }

        private void InitPageRouter()
        {
            //Callback to reload provider
            void onRouterReloaded(IPageRouter old, IPageRouter current)
            {
                _serviceGroups.TryForeach(sg => sg.UpdatePageRouter(current));
            }

            try
            {

                //get the loader that contains the single page router
                WebPluginLoader? routerLoader = _pluginLoaders
                    .Where(static s => s.ExposesType<IPageRouter>())
                    .SingleOrDefault();

                //If router has been supplied, load it
                if (routerLoader != null)
                {
                    //Get initial value
                    IPageRouter sp = (routerLoader.GetLoaderForSingleType<IPageRouter>()!.Plugin as IPageRouter)!;

                    //Init inital provider
                    onRouterReloaded(null!, sp);

                    //Register reload event
                    routerLoader.RegisterListenerForSingle<IPageRouter>(onRouterReloaded);
                }
            }
            catch (InvalidOperationException)
            {
                throw new TypeLoadException("More than one page router plugin was defined in the plugin directory, cannot continue");
            }
        }

        protected override void Free()
        {
            //Dispose loaders
            _pluginLoaders.TryForeach(static pl => pl.Dispose());
            _pluginLoaders.Clear();
            _serviceGroups.Clear();
        }
    }
}
