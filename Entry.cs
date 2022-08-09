using System;
using System.IO;
using System.Net;
using System.Data;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Net.Security;
using System.IO.Compression;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography.X509Certificates;

using Serilog;

using VNLib.Utils.IO;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Net.Http;
using VNLib.Net.Transport;
using VNLib.Plugins;
using VNLib.Plugins.Runtime;
using VNLib.Plugins.Essentials.Content;
using VNLib.Plugins.Essentials.Sessions;
using HttpVersion = VNLib.Net.Http.HttpVersion;
using VNLib.Utils;

/*
 * Arguments
 * --config <config_path>
 * -v --verbose
 * -d --debug
 * -vv double verbose mode (logs all app-domain events)
 * -s --silent silent logging mode, does not pring logs to the console, only to output files
 * --log-http prints raw http requests to the application log
 */

#nullable enable

namespace VNLib.WebServer
{
    static class Entry
    {
        private static readonly DirectoryInfo EXE_DIR = new(Environment.CurrentDirectory);
        private static readonly IPEndPoint DefaultInterface = new(IPAddress.Any, 80);
        private static readonly Regex DefaultRootRegex = new(@"(\/\.\.)|(\\\.\.)|[\[\]^*<>|`~'\n\r\t\n]|(\s$)|^(\s)", RegexOptions.Compiled);

        private static readonly TCPConfig BaseTcpConfig = new()
        {
            AcceptThreads = (uint)12,
            InitialReceiveTimeout = 2000,
            KeepaliveInterval = 4,
            TcpKeepalive = false,
            ListenerPriority = ThreadPriority.Normal,
            TcpKeepAliveTime = 4,
            CacheQuota = 0,
        };

        private const string DEFAULT_CONFIG_PATH = "config.json";
        private const string DEFUALT_PLUGIN_DIR = "plugins";
      
        private const string HOSTS_CONFIG_PROP_NAME = "virtual_hosts";
        private const string SERVER_ERROR_FILE_PROP_NAME = "error_files";

        private const string SERVER_ENDPOINT_PROP_NAME = "interface";
        private const string SERVER_ENDPOINT_PORT_PROP_NAME = "port";
        private const string SERVER_ENDPOINT_IP_PROP_NAME = "address";
        private const string SERVER_CERT_PROP_NAME = "cert";
        private const string SERVER_HOSTNAME_PROP_NAME = "hostname";
        private const string SERVER_ROOT_PATH_PROP_NAME = "path";
        private const string SESSION_TIMEOUT_PROP_NAME = "max_execution_time_ms";
        private const string SERVER_DEFAULT_FILE_PROP_NAME = "default_files";
        private const string SERVER_DENY_EXTENSIONS_PROP_NAME = "default_files";
        private const string SERVER_CONTENT_SEC_PROP_NAME = "content_security_policy";
        private const string SERVER_PATH_FILTER_PROP_NAME = "path_filter";
        private const string SERVER_REFER_POLICY_PROP_NAME = "refer_policy";
        private const string SERVER_CORS_ENEABLE_PROP_NAME = "enable_cors";
        private const string SERVER_HSTS_HEADER_PROP_NAME = "hsts_header";
        private const string SERVER_CACHE_DEFAULT_PROP_NAME = "cache_default_sec";
        private const string UPSTREAM_TRUSTED_SERVERS_PROP = "upstream_servers";

        private const string HTTP_CONF_PROP_NAME = "http";

        private const string PLUGINS_PROP_NAME = "plugins";

        private const string SERVER_WHITELIST_PROP_NAME = "whitelist";

        delegate IntPtr HeapCreate(long flOptions, ulong dwInitialSize, ulong dwMaximumSize);

        static int Main(string[] args)
        {
            //Set the RPMalloc env var for the process
            if (args.Contains("--rpmalloc"))
            {
                //Set initial env to use the rpmalloc allocator for the default heaps
                Environment.SetEnvironmentVariable(Memory.SHARED_HEAP_TYPE_ENV, "rpmalloc", EnvironmentVariableTarget.Process);
            }
            //Setup logger configs
            LoggerConfiguration sysLogConfig = new();
            LoggerConfiguration appLogConfig = new();
            //Check log verbosity level and configure logger minimum levels
            InitConsoleLog(args, sysLogConfig, "System");
            InitConsoleLog(args, appLogConfig, "Application");
            //try to load the json configuration file
            using JsonDocument config = LoadConfig(args);
            if (config == null)
            {
                appLogConfig.CreateLogger().Error("No configuration file was found");
                return -1;
            }
            //Init file logs
            InitLogs(config, "sys_log", "System", sysLogConfig);
            InitLogs(config, "app_log", "Application", appLogConfig);
            //Create the log provider wrappers
            using VLogProvider SystemLog = new(sysLogConfig);
            using VLogProvider ApplicationLog = new(appLogConfig);
            //Setup the app-domain listener
            InitAppDomainListener(args, ApplicationLog);
            //get the http conf
            HttpConfig? http = GetHttpConfig(config, args, SystemLog, ApplicationLog);
            //If no http config is defined, we cannot continue
            if (!http.HasValue)
            {
                return -1;
            }
            ApplicationLog.Verbose("Loading virtual hosts");
            //Get web roots
            List<BasicServerRoot> allRoots = LoadRoots(config, ApplicationLog);
            if (allRoots == null)
            {
                ApplicationLog.Error("No virtual hosts were defined, exiting");
                return 0;
            }
            //Get new server list
            List<HttpServer> servers = new();
            //Load non-ssl servers
            InitServers(servers, allRoots, SystemLog, http.Value);
            //Setup cancelation source to cancel running services 
            using CancellationTokenSource cancelSource = new();

            ApplicationLog.Information("Starting listeners...");
            try
            {
                //Start servers
                servers.ForEach(s => s.Start(cancelSource.Token));
            }
            catch (Exception ex)
            {
                ApplicationLog.Error(ex);
                return -1;
            }
            List<WebPluginLoader> plugins = new();
            //Load plugins
            LoadPlugins(plugins, config, ApplicationLog, allRoots);
            //Register cancelation to unload plugins (and oauth2 if loaded)
            cancelSource.Token.Register(() =>
            {
                //Dispose plugins
                plugins.TryForeach(static (plugin) =>
                {
                    using (plugin)
                    {
                        plugin.UnloadAll();
                    }
                });
            });
            using ManualResetEventSlim ShutdownEvent = new(false);
            //Register console cancel to cause cleanup
            Console.CancelKeyPress += (object sender, ConsoleCancelEventArgs e) =>
            {
                e.Cancel = true;
                ShutdownEvent.Set();
            };
            //Start listening for commands on a background thread, so it does not interfere with async tasks on tp threads
            Thread consoleListener = new(() =>
            {
                while (!ShutdownEvent.IsSet)
                {
                    string[]? s = Console.ReadLine()?.Split(' ');
                    if (s == null)
                    {
                        continue;
                    }
                    switch (s[0].ToLower())
                    {
                        //handle plugin
                        case "p":
                            {
                                if (s.Length < 3)
                                {
                                    Console.WriteLine("Plugin name and command are required");
                                    break;
                                }
                                LivePlugin? plugin = plugins.GetPluginByName(s[1]);
                                if (plugin == null)
                                {
                                    Console.WriteLine("Plugin not found");
                                    break;
                                }
                                //Join remianing args back to string and pass to plugin
                                plugin.SendConsoleMessage(string.Join(' ', s));
                            }
                            break;
                        case "reload":
                            {
                                try
                                {
                                    //Reload all plugins
                                    plugins.TryForeach(static p => p.ReloadPlugin());
                                }
                                catch (Exception ex)
                                {
                                    ApplicationLog.Error(ex);
                                }
                            }
                            break;
                        case "stats":
                            {
                                int gen0 = GC.CollectionCount(0);
                                int gen1 = GC.CollectionCount(1);
                                int gen2 = GC.CollectionCount(2);
                                ApplicationLog.Debug("Collection Gen0 {gen0} Gen1 {gen1} Gen2 {gen2}", gen0, gen1, gen2);
                                GCMemoryInfo mi = GC.GetGCMemoryInfo();
                                ApplicationLog.Debug("Compacted {cp} Last Size {lz}kb, Pause % {pa}", mi.Compacted, mi.HeapSizeBytes / 1024, mi.PauseTimePercentage);
                                ApplicationLog.Debug("High watermark {hw}kb Current Load {cc}kb", mi.HighMemoryLoadThresholdBytes / 1024, mi.MemoryLoadBytes / 1024);
                                ApplicationLog.Debug("Fargmented kb {frag} Concurrent {cc}", mi.FragmentedBytes / 1024, mi.Concurrent);
                                ApplicationLog.Debug("Pending finalizers {pf} Pinned Objects {pinned}", mi.FinalizationPendingCount, mi.PinnedObjectsCount);
                            }
                            break;
                        case "collect":
                            servers.ForEach(static a => a.CacheHardClear());
                            GC.Collect(2, GCCollectionMode.Forced, false, true);
                            GC.WaitForFullGCComplete();
                            break;
                        case "stop":
                            ShutdownEvent.Set();
                            return;
                    }
                }
            })
            {
                //Allow the main thread to exit
                IsBackground = true
            };
            //Start listener thread
            consoleListener.Start();
            //Wait for process cleanup/exit
            ShutdownEvent.Wait();

            ApplicationLog.Information("Stopping server");
            //Stop all services 
            cancelSource.Cancel();
            //Wait for all plugins to unload and cleanup (temporary)
            Thread.Sleep(500);
            //Cleanup servers
            foreach (HttpServer server in servers)
            {
                server.Dispose();
            }
            return 0;
        }

        #region config
        /// <summary>
        /// Initializes the configuration DOM from the specified cmd args 
        /// or the default configuration path
        /// </summary>
        /// <param name="args">The command-line-arguments</param>
        /// <returns>A new <see cref="JsonDocument"/> that contains the application configuration</returns>
        private static JsonDocument LoadConfig(string[] args)
        {
            //Search for a configuration file path in argument
            int index = args.ToList().IndexOf("--config") + 1;
            //Get the config path or default config
            string configPath = index > 0 ? args[index] : Path.Combine(EXE_DIR.FullName, DEFAULT_CONFIG_PATH);
            if (!FileOperations.FileExists(configPath))
            {
                return null;
            }
            //Open the config file
            using FileStream fs = new(configPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
            return JsonDocument.Parse(fs);
        }
        #endregion

        #region Logging

        private static void InitConsoleLog(string[] args, LoggerConfiguration conf, string logName)
        {
            //Set verbosity level, defaul to informational
            if (args.Contains("-v"))
            {
                conf.MinimumLevel.Verbose();
            }
            else if (args.Contains("-d"))
            {
                conf.MinimumLevel.Debug();
            }
            else
            {
                conf.MinimumLevel.Information();
            }
            //Setup loggers to write to console unless the -s silent arg is set
            if (!args.Contains("-s") && !args.Contains("--silent"))
{
                string template = $"{{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz}} [{{Level:u3}}] {logName} {{Message:lj}}{{NewLine}}{{Exception}}";
                _ = conf.WriteTo.Console(outputTemplate: template);
            }
        }
        private static void InitLogs(JsonDocument config, string elPath, string logName, LoggerConfiguration logConfig)
        {
            string? filePath = null;
            string? template = null;
            //try to get the log config object
            if(config.RootElement.TryGetProperty(elPath, out JsonElement logEl))
            {
                filePath = logEl.GetPropString("path");
                template = logEl.GetPropString("template");
            }
            //Set default objects
            filePath ??= Path.Combine(EXE_DIR.FullName, $"{elPath}.txt");
            template ??= $"{{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz}} [{{Level:u3}}] {logName} {{Message:lj}}{{NewLine}}{{Exception}}";
            //Configure the log file writer
            logConfig.WriteTo.File(filePath, buffered: true, outputTemplate: template);
        }
        #endregion
       
        /// <summary>
        /// Loads all server roots from the configuration file
        /// </summary>
        /// <param name="config">The application configuration to load</param>
        /// <param name="log"></param>
        /// <returns>A list of <see cref="WebRoot"/>s that make up the server endpoints</returns>
        private static List<BasicServerRoot> LoadRoots(JsonDocument config, ILogProvider log)
        {
            try
            {
                List<BasicServerRoot> roots = new();
                //Enumerate all roots
                foreach (JsonElement rootEl in config.RootElement.GetProperty(HOSTS_CONFIG_PROP_NAME).EnumerateArray())
                {
                    //Get root config as dict
                    IReadOnlyDictionary<string, JsonElement> rootConf = rootEl.EnumerateObject().ToDictionary(static kv => kv.Name, static kv => kv.Value);

                    //Get the hostname and path of the root
                    string? hostname = rootConf[SERVER_HOSTNAME_PROP_NAME].GetString();
                    string? rootPath = rootConf[SERVER_ROOT_PATH_PROP_NAME].GetString();

                    //Setup a default service interface
                    IPEndPoint serverEndpoint = DefaultInterface;
                    {
                        //Get the interface binding for this site
                        if (rootConf.TryGetValue(SERVER_ENDPOINT_PROP_NAME, out JsonElement interfaceEl))
                        {
                            //Get the stored IP address
                            string ipaddr = interfaceEl.GetProperty(SERVER_ENDPOINT_IP_PROP_NAME).GetString()!;
                            IPAddress addr = IPAddress.Parse(ipaddr);
                            //Get the port
                            int port = interfaceEl.GetProperty(SERVER_ENDPOINT_PORT_PROP_NAME).GetInt32();
                            //create the new interface
                            serverEndpoint = new(addr, port);
                        }
                    }
                    X509Certificate? cert = null;
                    {
                        //Try to get the cert for the app
                        if (rootConf.TryGetValue(SERVER_CERT_PROP_NAME, out JsonElement certPath))
                        {
                            //Load the cert and load it to the store
                            cert = X509Certificate.CreateFromCertFile(certPath.GetString()!);
                        }
                    }
                    //Allow site to define a regex filter pattern
                    Regex pathFilter = DefaultRootRegex;
                    {
                        if (rootConf.TryGetValue(SERVER_PATH_FILTER_PROP_NAME, out JsonElement rootRegexEl))
                        {
                            pathFilter = new(rootRegexEl.GetString()!);
                        }
                    }
                    //Build error files
                    Dictionary<HttpStatusCode, FailureFile> ff;
                    {
                        //if a failure file array is specified, capure all files and
                        if (rootConf.TryGetValue(SERVER_ERROR_FILE_PROP_NAME, out JsonElement errEl))
                        {
                            IEnumerable<KeyValuePair<HttpStatusCode, FailureFile>> ffs = (from f in errEl.EnumerateArray()
                                                                                          select new KeyValuePair<HttpStatusCode, FailureFile>(
                                                                                              (HttpStatusCode)f.GetProperty("code").GetInt32(),
                                                                                              new((HttpStatusCode)f.GetProperty("code").GetInt32(),
                                                                                              f.GetProperty("path").GetString())));
                            ff = new(ffs);
                        }
                        else
                        {
                            ff = new();
                        }
                    }
                    //Find upstream servers
                    HashSet<IPAddress> upstreamServers = new();
                    {
                        //See if element is set
                        if (rootConf.TryGetValue(UPSTREAM_TRUSTED_SERVERS_PROP, out JsonElement upstreamEl))
                        {
                            //hash endpoints 
                            upstreamServers = upstreamEl.EnumerateArray().Select(static addr => IPAddress.Parse(addr.GetString()!)).ToHashSet();
                        }
                    }
                    //Check Whitelist
                    HashSet<IPAddress>? whiteList = null;
                    {
                        //See if whitelist is defined
                        if(rootConf.TryGetValue(SERVER_WHITELIST_PROP_NAME, out JsonElement wlEl))
                        {
                            whiteList = wlEl.EnumerateArray().Select(static addr => IPAddress.Parse(addr.GetString()!)).ToHashSet();
                            log.Information("Found {c} addresses in whitelist for {host}", whiteList.Count.ToString(), hostname);
                        }
                    }
                    HashSet<string> excludedExtensions = new();
                    {
                        if (rootConf.TryGetValue(SERVER_DENY_EXTENSIONS_PROP_NAME, out JsonElement denyEl))
                        {
                            //get blocked extensions for the root
                            excludedExtensions = denyEl.EnumerateArray().Select(static el => el.GetString()).ToHashSet()!;
                        }
                    }
                    List<string> defaultFiles = new();
                    {
                        if (rootConf.TryGetValue(SERVER_DEFAULT_FILE_PROP_NAME, out JsonElement defFileEl))
                        {
                            //Get blocked extensions for the root
                            defaultFiles = defFileEl.EnumerateArray().Select(static s => s.GetString()).ToList()!;
                        }
                    }
                    //Get root exec timeout
                    uint timeoutMs = config.RootElement.GetProperty(SESSION_TIMEOUT_PROP_NAME).GetUInt32();
                    //Create a new server root 
                    BasicServerRoot root = new(rootPath, hostname, log, (int) timeoutMs)
                    {
                        //Set optional whitelist
                        WhiteList = whiteList,
                        //Set required upstream servers
                        upstreamServers = upstreamServers,
                        FailureFiles = new(ff),
                        //Set csp from config
                        ContentSecurityPolicy = rootConf.GetPropString(SERVER_CONTENT_SEC_PROP_NAME),
                        //store certificate
                        Certificate = cert,
                        //Set inerface
                        ServerEndpoint = serverEndpoint,
                        PathFilter = pathFilter,
                        //Get optional security config options
                        RefererPolicy = rootConf.GetPropString(SERVER_REFER_POLICY_PROP_NAME),
                        allowCors = rootConf.TryGetValue(SERVER_CORS_ENEABLE_PROP_NAME, out JsonElement corsEl) && corsEl.GetBoolean(),
                        HSTSHeader = rootConf.GetPropString(SERVER_HSTS_HEADER_PROP_NAME),
                        CacheDefault = TimeSpan.FromSeconds(rootConf[SERVER_CACHE_DEFAULT_PROP_NAME].GetInt32()),
                        excludedExtensions = excludedExtensions,
                        defaultFiles = new(defaultFiles)
                    };
                    //Add root to the list
                    roots.Add(root);
                    log.Information("Found virtual host {ep} on {if}, with TLS {tls}, upstream servers {us}", hostname, serverEndpoint, cert != null, upstreamServers);
                }
                return roots;
            }
            catch (KeyNotFoundException kne)
            {
                log.Warn("Missing required configuration varaibles {var}", kne.Message);
            }
            catch (FormatException fe)
            {
                log.Error("Invalid IP address {err}", fe.Message);
            }
            catch(Exception ex)
            {
                log.Error(ex);
            }
            return null;
        }
       
        /// <summary>
        /// Loads the static <see cref="HttpConfig"/> object
        /// from the application config
        /// </summary>
        /// <param name="config">The application config</param>
        /// <param name="sessions">The session config to use</param>
        /// <param name="sysLog">The "system" logger</param>
        /// <param name="appLog">The "application" logger</param>
        /// <returns>Null if the configuration object is unusable, a new <see cref="HttpConfig"/> struct if parsing was successful</returns>
        private static HttpConfig? GetHttpConfig(JsonDocument config, string[] args, ILogProvider sysLog, ILogProvider appLog)
        {
            try
            {
                //Get the http element
                IReadOnlyDictionary<string, JsonElement> httpEl = config.RootElement.GetProperty(HTTP_CONF_PROP_NAME)
                                                                            .EnumerateObject()
                                                                            .ToDictionary(static k => k.Name, static v => v.Value);
                HttpConfig conf = new(sysLog)
                {
                    RequestDebugLog = args.Contains("--log-http") ? appLog : null,
                    CompressionLevel = (CompressionLevel)httpEl["compression_level"].GetInt32(),
                    CompressionLimit = httpEl["compression_limit"].GetInt32(),
                    DefaultHttpVersion = HttpHelpers.ParseHttpVersion(httpEl["default_version"].GetString()),
                    FormDataBufferSize = httpEl["multipart_max_buffer"].GetInt32(),
                    MaxFormDataUploadSize = httpEl["multipart_max_size"].GetInt32(),
                    MaxUploadSize = httpEl["max_entity_size"].GetInt32(),
                    TransportKeepalive = httpEl["keepalive_ms"].GetTimeSpan(TimeParseType.Milliseconds),
                    HeaderBufferSize = httpEl["header_buf_size"].GetInt32(),
                    ActiveSocketRecvTimeout = (int)TimeSpan.FromSeconds(10).TotalMilliseconds,
                    MaxRequestHeaderCount = httpEl["max_request_header_count"].GetInt32(),
                    MaxOpenConnections = httpEl["max_connections"].GetInt32(),
                    HttpEncoding = Encoding.ASCII,
                    DiscardBufferSize = 64 * 1024,
                    ResponseHeaderBufferSize = 16 * 1024
                };
                return conf.DefaultHttpVersion == HttpVersion.NotSupported
                    ? throw new Exception("default_version is invalid, specify an RFC formatted http version 'HTTP/x.x'")
                    : conf;
            }
            catch (KeyNotFoundException kne)
            {
                appLog.Error("Missing required HTTP configuration varaibles {var}", kne.Message);
            }
            catch (Exception ex)
            {
                appLog.Error(ex, "Check your HTTP configuration object");
            }
            return null;
        }
        /// <summary>
        /// Initializes all HttpServers that may use secure 
        /// or insecure transport.
        /// </summary>
        /// <param name="servers">A list to add configured servers to</param>
        /// <param name="roots">An enumeration of all sites/roots to route incomming connections</param>
        /// <param name="sysLog">The "system" logger</param>
        /// <param name="httpConf">The http configuraiton to use when initializing servers</param>
        private static void InitServers(List<HttpServer> servers, IEnumerable<BasicServerRoot> roots, ILogProvider sysLog, HttpConfig httpConf)
        {
            //Get a distinct list of the server interfaces that are required to setup hosts
            IEnumerable<IPEndPoint> interfaces = (from root in roots select root.ServerEndpoint).Distinct();
            foreach (IPEndPoint serverEp in interfaces)
            {
                SslServerAuthenticationOptions? sslAuthOptions = null;
                //get all roots that use the same Ip/port
                IEnumerable<BasicServerRoot> rootsForEp = (from root in roots where root.ServerEndpoint.Equals(serverEp) select root);
                //Get all roots for the specified endpoints that have certificates
                IEnumerable<BasicServerRoot> sslRoots = (from root in rootsForEp where root.Certificate != null select root);
                //See if any ssl roots are configured
                if (sslRoots.Any())
                {
                    //Setup a cert lookup for all roots that defined certs
                    Dictionary<string, X509Certificate> certLookup = sslRoots.ToDictionary(root => root.Hostname, root => root.Certificate)!;
                    //If the wildcard hostname is set save a local copy
                    X509Certificate defaultCert = certLookup.GetValueOrDefault("*", null);
                    //Build the server auth options
                    sslAuthOptions = new()
                    {
                        //Local callback for cert selection
                        ServerCertificateSelectionCallback = delegate (object sender, string? hostName)
                        {
                            // use the default cert if the hostname is not specified
                            return certLookup.GetValueOrDefault(hostName, defaultCert);
                        },
                        AllowRenegotiation = true,
                        RemoteCertificateValidationCallback = delegate (object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
                        {
                            return true;
                        }
                    };
                }
                //Init a new TCP config
                TCPConfig tcp = new()
                {
                    LocalEndPoint = serverEp,
                    Log = sysLog,
                    AuthenticationOptions = sslAuthOptions,
                    //Copy from base config
                    AcceptThreads = BaseTcpConfig.AcceptThreads,
                    InitialReceiveTimeout = BaseTcpConfig.InitialReceiveTimeout,
                    TcpKeepAliveTime = BaseTcpConfig.TcpKeepAliveTime,
                    KeepaliveInterval = BaseTcpConfig.KeepaliveInterval,
                    ListenerPriority = BaseTcpConfig.ListenerPriority,
                    TcpKeepalive = BaseTcpConfig.TcpKeepalive,
                    CacheQuota = BaseTcpConfig.CacheQuota
                };
                //Create the new server
                HttpServer server = new(httpConf, tcp, rootsForEp);
                //Add the server to the list
                servers.Add(server);
            }
        }

        #region Plugins

        static readonly string PluginFileExtension = OperatingSystem.IsWindows() ? ".dll" : ".so";

        private static void LoadPlugins(List<WebPluginLoader> plugins, JsonDocument config, ILogProvider appLog, IEnumerable<BasicServerRoot> roots)
        {
            //Try to get the plugin configuration
            if(!config.RootElement.TryGetProperty(PLUGINS_PROP_NAME, out JsonElement pluginEl))
            {
                return;
            }
            //Get the plugin directory, or set to default
            string pluginDir = pluginEl.GetPropString("path") ?? Path.Combine(EXE_DIR.FullName, DEFUALT_PLUGIN_DIR);
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
            IEnumerable<string> pluginPaths = dirs.Where(pdir =>
            {
                string FilePath = Path.ChangeExtension(Path.Combine(pdir.FullName, pdir.Name), PluginFileExtension);
                return FileOperations.FileExists(FilePath);
            })
            //Return the name of the dll file to import
            .Select(pdir =>
            {
                return Path.ChangeExtension(Path.Combine(pdir.FullName, pdir.Name), PluginFileExtension);
            });
            List<Task> loading = new();
            foreach (string pluginPath in pluginPaths)
            {
                async Task Load()
                {
                    WebPluginLoader plugin = new(pluginPath, config, appLog, hotReload, hotReload);
                    try
                    {
                        await plugin.InitLoaderAsync();
                        //Load all endpoints
                        plugin.LoadEndpoints(roots);
                        //Listen for reload events to remove and re-add endpoints
                        plugin.Reloaded += delegate (object? sender, List<LivePlugin> lp)
                        {
                            WebPluginLoader wpl = (sender as WebPluginLoader)!;
                            wpl.LoadEndpoints(roots);
                        };
                        //Add to list
                        plugins.Add(plugin);
                    }
                    catch (Exception ex)
                    {
                        appLog.Error(ex);
                        plugin.Dispose();
                    }
                }
                loading.Add(Load());
            }
            //wait for loading to completed
            Task.WaitAll(loading.ToArray());
            {
                //get the loader that contains the single session provider
                WebPluginLoader? sessionLoader = (from pp in plugins
                                                 where pp.GetLoaderForSingleType<ISessionProvider>() != null
                                                 select pp)
                                                .SingleOrDefault();
                //Method to load sessions to all roots
                static void LoadSessions(IEnumerable<BasicServerRoot> roots, ISessionProvider provider)
                {
                    foreach (BasicServerRoot root in roots)
                    {
                        root.SetSessionProvider(provider);
                    }
                }
                //If session provider has been supplied, load it
                if (sessionLoader != null)
                {
                    //Get the session provider from the plugin loader
                    ISessionProvider sp = (sessionLoader.GetLoaderForSingleType<ISessionProvider>()!.Plugin as ISessionProvider)!;
                    //Register listener for plugin changes
                    sessionLoader.RegisterListenerForSingle(delegate (ISessionProvider current, ISessionProvider loaded)
                    {
                        //Reload the provider
                        LoadSessions(roots, loaded);
                    });
                    //Load sessions
                    LoadSessions(roots, sp);
                }
            }
            //Loader for the page router
            {
                static void LoadRouter(IEnumerable<BasicServerRoot> roots, IPageRouter router)
                {
                    foreach (BasicServerRoot root in roots)
                    {
                        root.SetPageRouter(router);
                    }
                }
                //Get the loader for the IPage router
                WebPluginLoader? routerLoader = (from pp in plugins
                                                where pp.GetLoaderForSingleType<IPageRouter>() != null
                                                select pp)
                                                .SingleOrDefault();
                if(routerLoader != null)
                {
                    //get the router instance
                    IPageRouter router = (routerLoader.GetLoaderForSingleType<IPageRouter>()!.Plugin as IPageRouter)!;
                    //Reigster reload listener
                    routerLoader.RegisterListenerForSingle(delegate (IPageRouter current, IPageRouter newRouter)
                    {
                        LoadRouter(roots, newRouter);
                    });
                    //Load the current router
                    LoadRouter(roots, router);
                }
            }
        }


        internal static void LoadEndpoints(this WebPluginLoader loader, IEnumerable<BasicServerRoot> roots)
        {
            foreach (var (endpoint, root) in from IEndpoint endpoint in loader.GetEndpoints()
                                             from BasicServerRoot root in roots
                                             select (endpoint, root))
            {
                //remove previous endpoints if set
                root.RemoveEndpoint(endpoint);
                //Add the new endpoint
                root.AddEndpoint(endpoint);
            }
        }

        internal static void InitAppDomainListener(string[] args, ILogProvider log)
        {
            AppDomain currentDomain = AppDomain.CurrentDomain;
            currentDomain.UnhandledException += delegate (object sender, UnhandledExceptionEventArgs e)
            {
                log.Fatal("UNHANDLED APPDOMAIN EXCEPTION \n {e}", e);
            };
            //If double verbose is specified, log app-domain messages
            if (args.Contains("-vv"))
            {
                currentDomain.FirstChanceException += delegate (object? sender, FirstChanceExceptionEventArgs e)
                {
                    log.Verbose("Exception occured in app-domain {mess}", e.Exception.Message);
                };
                currentDomain.AssemblyLoad += delegate (object? sender, AssemblyLoadEventArgs args)
                {
                    log.Verbose("Assembly loaded {asm} to appdomain {domain}", args.LoadedAssembly.FullName, currentDomain.FriendlyName);
                };
                currentDomain.DomainUnload += delegate (object? sender, EventArgs e)
                {
                    log.Verbose("Domain {domain} unloaded", currentDomain.FriendlyName);
                };
            }
        }


        internal static LivePlugin? GetPluginByName(this IEnumerable<WebPluginLoader> plugins, string name)
        {
            return plugins.SelectMany(static p => p.LivePlugins)
                .Where(p => p.PluginName.Equals(name, StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault();
        }

        #endregion
    }
}
