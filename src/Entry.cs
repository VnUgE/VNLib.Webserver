/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: Entry.cs 
*
* Entry.cs is part of VNLib.WebServer which is part of the larger 
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
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Net.Security;
using System.IO.Compression;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.ExceptionServices;

using VNLib.Utils.IO;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Utils.Memory.Diagnostics;
using VNLib.Net.Http;
using VNLib.Net.Transport.Tcp;
using VNLib.Plugins.Essentials.ServiceStack;

using VNLib.WebServer.Plugins;
using VNLib.WebServer.Transport;
using VNLib.WebServer.TcpMemoryPool;
using VNLib.WebServer.RuntimeLoading;

/*
* Arguments
* --config <config_path>
* -v --verbose
* -d --debug
* -vv double verbose mode (logs all app-domain events)
* -s --silent silent logging mode, does not print logs to the console, only to output files
* --log-http prints raw http requests to the application log
* --rpmalloc to force enable the rpmalloc library loading for the Memory class
* --no-plugins disables plugin loading
* -t --threads specify the number of accept threads
* --use-os-ciphers disables hard-coded cipher suite and lets the OS decide the ciphersuite for ssl connections
* --input-off disables listening on stdin for commands
* --inline-scheduler uses the inline scheduler for the pipeline
* --dump-config dumps the JSON config to the console
*/


namespace VNLib.WebServer
{

    static partial class Entry
    {
        const string STARTUP_MESSAGE =
@"VNLib Copyright (C) Vaughn Nugent
This program comes with ABSOLUTELY NO WARRANTY.
Licensing for this software and other libraries can be found at https://www.vaughnnugent.com/resources/software
Starting...
";


        private static readonly DirectoryInfo EXE_DIR = new(Environment.CurrentDirectory);
        private static readonly IPEndPoint DefaultInterface = new(IPAddress.Any, 80);
        private static readonly Regex DefaultRootRegex = new(@"(\/\.\.)|(\\\.\.)|[\[\]^*<>|`~'\n\r\t\n]|(\s$)|^(\s)", RegexOptions.Compiled);

        private static readonly TCPConfig BaseTcpConfig = new()
        {
            KeepaliveInterval = 4,
            TcpKeepalive = false,
            TcpKeepAliveTime = 4,
            CacheQuota = 0,
            //Max 640k per connection to be pre-loaded
            MaxRecvBufferData = 10 * 64 * 1024,
            BackLog = 1000
        };

        /*
         * Chunked encoding is only used when compression is enabled
         * and the output block size is fixed, usually some multiple 
         * of 8k. So this value should be the expected size of the 
         * block to trigger a write to the transport. 
         * 
         * This value should be larger than the expected block size,
         * otherwise this may cause excessive double buffer overhead.
         */
        private const int CHUNCKED_ACC_BUFFER_SIZE = 64 * 1024;

        private const string DEFAULT_CONFIG_PATH = "config.json";

        private const string HOSTS_CONFIG_PROP_NAME = "virtual_hosts";
        private const string SERVER_ERROR_FILE_PROP_NAME = "error_files";

        private const string SERVER_ENDPOINT_PROP_NAME = "interface";
        private const string SERVER_ENDPOINT_PORT_PROP_NAME = "port";
        private const string SERVER_ENDPOINT_IP_PROP_NAME = "address";
        private const string SERVER_CERT_PROP_NAME = "cert";
        private const string SERVER_PRIV_KEY_PROP_NAME = "privkey";
        private const string SERVER_SSL_PROP_NAME = "ssl";
        private const string SERVER_SSL_CREDS_REQUIRED_PROP_NAME = "client_cert_required";
        private const string SERVER_HOSTNAME_PROP_NAME = "hostname";
        private const string SERVER_HOSTNAME_ARRAY_PROP_NAME = "hostnames";
        private const string SERVER_ROOT_PATH_PROP_NAME = "path";
        private const string SESSION_TIMEOUT_PROP_NAME = "max_execution_time_ms";
        private const string SERVER_DEFAULT_FILE_PROP_NAME = "default_files";
        private const string SERVER_DENY_EXTENSIONS_PROP_NAME = "default_files";
        private const string SERVER_PATH_FILTER_PROP_NAME = "path_filter";
        private const string SERVER_CORS_ENEABLE_PROP_NAME = "enable_cors";
        private const string SERVER_CACHE_DEFAULT_PROP_NAME = "cache_default_sec";
        private const string SERVER_CORS_AUTHORITY_PROP_NAME = "cors_allowed_authority";
        private const string DOWNSTREAM_TRUSTED_SERVERS_PROP = "downstream_servers";
        private const string SERVER_HEADERS_PROP_NAME = "headers";
        private const string SERVER_BROWSER_ONLY_PROP_NAME = "browser_only_files";

        private const string HTTP_CONF_PROP_NAME = "http";

        private const string SERVER_WHITELIST_PROP_NAME = "whitelist";

        private const string LOAD_DEFAULT_HOSTNAME_VALUE = "[system]";

        private const string PLUGINS_CONFIG_PROP_NAME = "plugins";


        static int Main(string[] args)
        {
            ProcessArguments procArgs = new(args);

            //Print the help menu
            if(args.Length == 0 || procArgs.HasArg("-h") || procArgs.HasArg("--help"))
            {
                PrintHelpMenu();
                return 0;
            }

            //Set the RPMalloc env var for the process
            if (procArgs.RpMalloc)
            {
                //Set initial env to use the rpmalloc allocator for the default heaps
                Environment.SetEnvironmentVariable(MemoryUtil.SHARED_HEAP_FILE_PATH, "rpmalloc.dll", EnvironmentVariableTarget.Process);
            }

            Console.WriteLine(STARTUP_MESSAGE);

            //Init log config builder
            ServerLogBuilder logBuilder = new();
            logBuilder.BuildForConsole(procArgs);

            //try to load the json configuration file
            using JsonDocument? config = LoadConfig(procArgs);
            if (config == null)
            {
                logBuilder.AppLogConfig.CreateLogger().Error("No configuration file was found");
                return -1;
            }

            //Build logs from config
            logBuilder.BuildFromConfig(config.RootElement);

            //Create the logger
            using ServerLogger logger = logBuilder.GetLogger();

            //Dump config to console
            if (procArgs.HasArg("--dump-config"))
            {
                DumpConfig(config, logger);
            }

            //Setup the app-domain listener
            InitAppDomainListener(procArgs, logger.AppLog);

            //get the http conf
            HttpConfig? http = GetHttpConfig(config, procArgs, logger);

            //If no http config is defined, we cannot continue
            if (!http.HasValue)
            {
                return -1;
            }

            logger.AppLog.Information("Building service stack, populating service domain...");

            //Init service stack
            using HttpServiceStack? serviceStack = BuildStack(logger, procArgs, http.Value, config);

            if(serviceStack == null)
            {
                logger.AppLog.Error("Failed to build service stack, no virtual hosts were defined, exiting");
                return 0;
            }

            logger.AppLog.Information("Starting listeners...");

            //Start servers
            serviceStack.StartServers();

            using ManualResetEvent ShutdownEvent = new(false);

            //Register console cancel to cause cleanup
            Console.CancelKeyPress += (object? sender, ConsoleCancelEventArgs e) =>
            {
                e.Cancel = true;
                ShutdownEvent.Set();
            };


            //Allow user to disable the console listener
            if (!procArgs.HasArg("--input-off"))
            {

                //Start listening for commands on a background thread, so it does not interfere with async tasks on tp threads
                Thread consoleListener = new(() => StdInListenerDoWork(ShutdownEvent, logger.AppLog, serviceStack))
                {
                    //Allow the main thread to exit
                    IsBackground = true
                };


                //Start listener thread
                consoleListener.Start();
            }


            logger.AppLog.Information("Main thread waiting for exit signal, press ctrl + c to exit");

            //Wait for process cleanup/exit
            ShutdownEvent.WaitOne();

            logger.AppLog.Information("Stopping service stack");

            //Wait for ss to exit
            serviceStack.StopAndWaitAsync().GetAwaiter().GetResult();

            //Wait for all plugins to unload and cleanup (temporary)
            Thread.Sleep(500);
            return 0;
        }

        static void PrintHelpMenu()
        {
            const string TEMPLATE =
@"
    VNLib.Webserver Copyright (C) 2023 Vaughn Nugent

    A high-performance, cross-platform, single process, webserver built on the .NET 6.0 Core runtime.

    Option flags:
        --config         <path>     - Specifies the path to the configuration file (relative or absolute)
        --input-off                 - Disables the STDIN listener, no runtime commands will be processed
        --rpmalloc                  - Force loads the rpmalloc dll for the platform from safe directories
        --inline-scheduler          - Enables inline scheduling for TCP transport IO processing
        --use-os-ciphers            - Overrides pre-configured TLS ciphers with OS provided ciphers
        --no-plugins                - Disables loading of dynamic plugins
        --log-http                  - Enables logging of HTTP request and response headers to the system logger
        --dump-config               - Dumps the JSON configuration to the console during loading
        -h, --help                  - Prints this help menu
        -t, --threads    <num>      - Specifies the number of socket accept threads. Defaults to processor count
        -s, --silent                - Disables all console logging
        -v, --verbose               - Enables verbose logging
        -d, --debug                 - Enables debug logging for the process and all plugins
        -vv                         - Enables very verbose logging (attaches listeners for app-domain events and logs them to the output)

    Your configuration file must be a JSON encoded file and be readable to the process. You may consider keeping it in a safe location
outside the application and only readable to this process.

    You should disable hot-reload for production environments, for security and performance reasons.

    You may consider using the --input-off flag to disable STDIN listening for production environments for security reasons.

    Usage:
        VNLib.Webserver --config <path> ... (other options)     #Starts the server from the configuration (basic usage)

";
            Console.WriteLine(TEMPLATE);
        }

        #region config

        /// <summary>
        /// Initializes the configuration DOM from the specified cmd args 
        /// or the default configuration path
        /// </summary>
        /// <param name="args">The command-line-arguments</param>
        /// <returns>A new <see cref="JsonDocument"/> that contains the application configuration</returns>
        private static JsonDocument? LoadConfig(ProcessArguments args)
        {
            //Get the config path or default config
            string configPath = args.GetArg("--config") ?? Path.Combine(EXE_DIR.FullName, DEFAULT_CONFIG_PATH);

            if (!FileOperations.FileExists(configPath))
            {
                return null;
            }

            //Open the config file
            using FileStream fs = new(configPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);

            //Allow comments
            JsonDocumentOptions jdo = new()
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            };

            return JsonDocument.Parse(fs, jdo);
        }

        private static void DumpConfig(JsonDocument doc, ServerLogger logger)
        {            
            //Dump the config to the console
            using VnMemoryStream ms = new();
            using (Utf8JsonWriter writer = new(ms, new JsonWriterOptions() { Indented = true }))
            {
                doc.WriteTo(writer);
            }

            string json = Encoding.UTF8.GetString(ms.AsSpan());
            logger.AppLog.Information("Dumping configuration to console...\n{c}", json);
        }

        #endregion

        private static HttpServiceStack? BuildStack(ServerLogger logger, ProcessArguments args, HttpConfig httpConfig, JsonDocument config)
        {
            IHttpServer BuildServer(ServiceGroup group)
            {
                //Get transport
                ITransportProvider transport = GetTransportForServiceGroup(group, logger.SysLog, args);

                //Build the http server
                return new HttpServer(httpConfig, transport, group.Hosts.Select(r => r.Processor));
            }

            //Init service stack
            HttpServiceStack stack = new HttpServiceStackBuilder()
                                    .WithDomainBuilder(collection => LoadRoots(config, logger.AppLog, collection))
                                    .WithHttp(BuildServer)
                                    .Build();

            //do not load plugins if disabled
            if (args.HasArg("--no-plugins"))
            {
                logger.AppLog.Information("Plugin loading disabled via options flag");
                return stack;
            }

            if (!config.RootElement.TryGetProperty(PLUGINS_CONFIG_PROP_NAME, out JsonElement plCfg))
            {
                logger.AppLog.Debug("No plugin configuration found");
                return stack;
            }

            try
            {
                bool hotReload = plCfg.TryGetProperty("hot_reload", out JsonElement hrEl) && hrEl.GetBoolean();

                //Set the reload delay
                TimeSpan delay = TimeSpan.FromSeconds(2);
                if (plCfg.TryGetProperty("reload_delay_sec", out JsonElement reloadDelayEl))
                {
                    delay = reloadDelayEl.GetTimeSpan(TimeParseType.Seconds);
                }

                PluginAssemblyLoaderFactory asmFactory = new((string asmFile) => new (asmFile)
                {
                    //we need to enable sharing to allow for IPlugin instances to be shared across domains
                    PreferSharedTypes = true,

                    IsUnloadable = hotReload,

                    //Load into memory to allow for hot-reload
                    LoadInMemory = hotReload,

                    //Enable file watching
                    WatchForReload = hotReload,
                    ReloadDelay = delay
                });

                //Build plugin config
                PluginLoadConfig conf = new()
                {
                    PluginErrorLog = logger.AppLog,
                    HostConfig = config.RootElement,

                    PluginDir = plCfg.TryGetProperty("path", out JsonElement pathEl) ? pathEl.GetString()! : "/plugins",

                    AssemblyLoaderFactory = asmFactory
                };

                const string PLUGIN_DATA_TEMPLATE =
@"
----------------------------------
 |      Plugin configuration:
 | Enabled: {enabled}
 | Directory: {dir}
 | Hot Reload: {hr}
 | Reload Delay: {delay}s
----------------------------------";

                logger.AppLog.Information(
                    PLUGIN_DATA_TEMPLATE,
                    true,
                    conf.PluginDir,
                    hotReload,
                    delay.TotalSeconds
                );

                //Wait for plugins to load
                stack.PluginManager.LoadPlugins(conf, logger.AppLog);

            }
            catch
            {
                //Dispose the stack
                stack.Dispose();
                throw;
            }

            return stack;
        }

        private const string FOUND_VH_TEMPLATE =
@"
--------------------------------------------------
 |           Found virtual host:
 | Hostnames: {hn}
 | Directory: {dir}
 | Listening on: {ep}
 | SSL: {ssl}, Client Cert Required: {cc}
 | Whitelist entries: {wl}
 | Downstream servers: {ds}
 | Cors Enabled: {enlb}
 | Allowed Cors Sites: {cors}
--------------------------------------------------";

        /// <summary>
        /// Loads all server roots from the configuration file
        /// </summary>
        /// <param name="config">The application configuration to load</param>
        /// <param name="log"></param>
        /// <remarks>A value that indicates if roots we loaded correctly, or false if errors occured and could not be loaded</remarks>
        private static bool LoadRoots(JsonDocument config, ILogProvider log, ICollection<IServiceHost> hosts)
        {
            try
            {
                //Enumerate all virtual host configurations
                foreach (JsonElement rootEl in config.RootElement.GetProperty(HOSTS_CONFIG_PROP_NAME).EnumerateArray())
                {
                    //execution timeout
                    TimeSpan execTimeout = config.RootElement.GetProperty(SESSION_TIMEOUT_PROP_NAME).GetTimeSpan(TimeParseType.Milliseconds);

                    //Inint config builder
                    VirtualHostConfigBuilder builder = new(rootEl, execTimeout);

                    //Get hostname array
                    string[] hostNames = builder.GetHostnameList();

                    //Get the configuration
                    VirtualHostConfig conf = builder.Build();

                    //Create directory if it doesnt exist yet
                    if (!Directory.Exists(conf.FileRoot))
                    {
                        Directory.CreateDirectory(conf.FileRoot);
                    }

                    //Create a new vritual host for every hostname using the same configuration
                    foreach(string hostName in hostNames)
                    {
                        //Substitute the dns hostname variable
                        string hn = hostName.Replace(LOAD_DEFAULT_HOSTNAME_VALUE, Dns.GetHostName(), StringComparison.OrdinalIgnoreCase);

                        //Create service host from the configuration and the hostname
                        RuntimeServiceHost host = new(hn, log, conf);

                        //Add root to the list
                        hosts.Add(host);
                    }

                    //Log the 
                    log.Information(
                        FOUND_VH_TEMPLATE,
                        hostNames,
                        conf.FileRoot,
                        conf.TransportEndpoint,
                        conf.Certificate != null,
                        conf.ClientCertRequired,
                        conf.WhiteList?.ToArray(),
                        conf.DownStreamServers?.ToArray(),
                        conf.AllowCors,
                        conf.AllowedCorsAuthority
                    );
                }
                return true;
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
            return false;
        }

        /// <summary>
        /// Loads the static <see cref="HttpConfig"/> object
        /// from the application config
        /// </summary>
        /// <param name="config">The application config</param>
        /// <returns>Null if the configuration object is unusable, a new <see cref="HttpConfig"/> struct if parsing was successful</returns>
        private static HttpConfig? GetHttpConfig(JsonDocument config, ProcessArguments args, ServerLogger logger)
        {
            try
            {
                //Get the http element
                IReadOnlyDictionary<string, JsonElement> httpEl = config.RootElement.GetProperty(HTTP_CONF_PROP_NAME)
                                                                            .EnumerateObject()
                                                                            .ToDictionary(static k => k.Name, static v => v.Value);
                HttpConfig conf = new(logger.SysLog, PoolManager.GetHttpPool())
                {
                    RequestDebugLog = args.LogHttp ? logger.AppLog : null,
                    CompressionLevel = (CompressionLevel)httpEl["compression_level"].GetInt32(),
                    CompressionLimit = httpEl["compression_limit"].GetInt32(),
                    CompressionMinimum = httpEl["compression_minimum"].GetInt32(),
                    DefaultHttpVersion = HttpHelpers.ParseHttpVersion(httpEl["default_version"].GetString()),                   
                    MaxFormDataUploadSize = httpEl["multipart_max_size"].GetInt32(),
                    MaxUploadSize = httpEl["max_entity_size"].GetInt32(),
                    ConnectionKeepAlive = httpEl["keepalive_ms"].GetTimeSpan(TimeParseType.Milliseconds),                  
                    ActiveConnectionRecvTimeout = httpEl["recv_timeout_ms"].GetInt32(),
                    SendTimeout = httpEl["send_timeout_ms"].GetInt32(),
                    MaxRequestHeaderCount = httpEl["max_request_header_count"].GetInt32(),
                    MaxOpenConnections = httpEl["max_connections"].GetInt32(),                  

                    //Buffer config update
                    BufferConfig = new()
                    {
                        RequestHeaderBufferSize = httpEl["header_buf_size"].GetInt32(),
                        ResponseHeaderBufferSize = httpEl["response_header_buf_size"].GetInt32(),
                        FormDataBufferSize = httpEl["multipart_max_buf_size"].GetInt32(),
                        ResponseBufferSize = httpEl["response_buf_size"].GetInt32(),
                        DiscardBufferSize = httpEl["request_discard_buf_size"].GetInt32(),
                        ChunkedResponseAccumulatorSize = CHUNCKED_ACC_BUFFER_SIZE,
                    },

                    HttpEncoding = Encoding.ASCII,
                };
                return conf.DefaultHttpVersion == Net.Http.HttpVersion.None
                    ? throw new ArgumentException("Your default HTTP version is invalid, specify an RFC formatted http version 'HTTP/x.x'", "default_version")
                    : conf;
            }
            catch (KeyNotFoundException kne)
            {
                logger.AppLog.Error("Missing required HTTP configuration variables {var}", kne.Message);
            }
            catch (Exception ex)
            {
                logger.AppLog.Error(ex, "Check your HTTP configuration object");
            }
            return null;
        }

        private static ITransportProvider GetTransportForServiceGroup(ServiceGroup group, ILogProvider sysLog, ProcessArguments args)
        {
            SslServerAuthenticationOptions? sslAuthOptions = null;

            //See if certs are defined
            if (group.Hosts.Where(static h => h.TransportInfo.Certificate != null).Any())
            {
                //If any hosts have ssl enabled, all shared endpoints MUST include a certificate to be bound to the same endpoint
                if(!group.Hosts.All(h => h.TransportInfo.Certificate != null))
                {
                    throw new ServerConfigurationException("One or more service hosts declared a shared endpoint with SSL enabled but not every host declared an SSL certificate for the shared interface");
                }

                //Build the server auth options for this transport provider
                sslAuthOptions = new ServerSslOptions(group.Hosts, args.HasArg("--use-os-ciphers"));
            }

            //Check cli args for inline scheduler
            bool inlineScheduler = args.HasArg("--inline-scheduler");

            //Check cli args thread count
            string? procCount = args.GetArg("-t") ?? args.GetArg("--threads");

            if(!uint.TryParse(procCount, out uint threadCount))
            {
                threadCount = (uint)Environment.ProcessorCount;
            }

            //Init a new TCP config
            TCPConfig tcpConf = new()
            {
                AcceptThreads = threadCount,

                //Service endpoint to listen on
                LocalEndPoint = group.ServiceEndpoint,
                Log = sysLog,

                //Copy from base config
                TcpKeepAliveTime = BaseTcpConfig.TcpKeepAliveTime,
                KeepaliveInterval = BaseTcpConfig.KeepaliveInterval,
                TcpKeepalive = BaseTcpConfig.TcpKeepalive,
                CacheQuota = BaseTcpConfig.CacheQuota,
                MaxRecvBufferData = BaseTcpConfig.MaxRecvBufferData,
                BackLog = BaseTcpConfig.BackLog,

                //Init buffer pool
                BufferPool = PoolManager.GetPool()
            };

            //Init new tcp server with/without ssl
            return sslAuthOptions != null ? 
                TcpTransport.CreateServer(in tcpConf, sslAuthOptions, inlineScheduler) 
                : TcpTransport.CreateServer(in tcpConf, inlineScheduler);
        }

        private static void StdInListenerDoWork(ManualResetEvent shutdownEvent, ILogProvider appLog, HttpServiceStack serviceStack)
        {
            appLog.Information("Listening for commands on stdin");

            while (shutdownEvent.WaitOne(0) == false)
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

                            string message = string.Join(' ', s);

                            bool sent = serviceStack.PluginManager.SendCommandToPlugin(s[1], message);

                            if (!sent)
                            {
                                Console.WriteLine("Plugin not found");
                            }
                        }
                        break;
                    case "reload":
                        {
                            try
                            {
                                //Reload all plugins
                                serviceStack.PluginManager.ForceReloadAllPlugins();
                            }
                            catch (Exception ex)
                            {
                                appLog.Error(ex);
                            }
                        }
                        break;
                    case "memstats":
                        {
                            const string MANAGED_HEAP_STATS = @"
         Managed Heap Stats
--------------------------------------
 Collections: 
   Gen0: {g0} Gen1: {g1} Gen2: {g2}

 Heap:
  High Watermark:    {hw} KB
  Last GC Heap Size: {hz} KB
  Current Load:      {ld} KB
  Fragmented:        {fb} KB

 Heap Info:
  Last GC concurrent? {con}
  Last GC compacted?  {comp}
  Pause time:         {pt} %
  Pending finalizers: {pf}
  Pinned objects:     {po}
";

                            //Collect gc info for managed heap stats
                            int gen0 = GC.CollectionCount(0);
                            int gen1 = GC.CollectionCount(1);
                            int gen2 = GC.CollectionCount(2);
                            GCMemoryInfo mi = GC.GetGCMemoryInfo();

                            appLog.Debug(MANAGED_HEAP_STATS,
                                gen0,
                                gen1,
                                gen2,
                                mi.HighMemoryLoadThresholdBytes / 1024,
                                mi.HeapSizeBytes / 1024,
                                mi.MemoryLoadBytes / 1024,
                                mi.FragmentedBytes / 1024,
                                mi.Concurrent,
                                mi.Compacted,
                                mi.PauseTimePercentage,
                                mi.FinalizationPendingCount,
                                mi.PinnedObjectsCount);

                            //Get heap stats
                            HeapStatistics hs = MemoryUtil.GetSharedHeapStats();

                            const string HEAPSTATS = @"
    Unmanaged Heap Stats
---------------------------
 userHeap? {rp}
 Allocated bytes:   {ab}
 Allocated handles: {h}
 Max block size:    {mb}
 Min block size:    {mmb}
 Max heap size:     {hs}
";

                            //Print unmanaged heap stats
                            appLog.Debug(HEAPSTATS,
                                MemoryUtil.IsUserDefinedHeap,
                                hs.AllocatedBytes,
                                hs.AllocatedBlocks,
                                hs.MaxBlockSize,
                                hs.MinBlockSize,
                                hs.MaxHeapSize);
                        }
                        break;
                    case "collect":
                        serviceStack.CollectCache();
                        GC.Collect(2, GCCollectionMode.Forced, false, true);
                        GC.WaitForFullGCComplete();
                        break;
                    case "stop":
                        shutdownEvent.Set();
                        return;
                }
            }
        }

        private static void InitAppDomainListener(ProcessArguments args, ILogProvider log)
        {
            AppDomain currentDomain = AppDomain.CurrentDomain;
            currentDomain.UnhandledException += delegate (object sender, UnhandledExceptionEventArgs e)
            {
                log.Fatal("UNHANDLED APPDOMAIN EXCEPTION \n {e}", e);
            };
            //If double verbose is specified, log app-domain messages
            if (args.DoubleVerbose)
            {
                log.Verbose("Double verbose mode enabled, registering app-domain listeners");

                currentDomain.FirstChanceException += delegate (object? sender, FirstChanceExceptionEventArgs e)
                {
                    log.Verbose(e.Exception, "Exception occured in app-domain ");
                };
                currentDomain.AssemblyLoad += delegate (object? sender, AssemblyLoadEventArgs args)
                {
                    log.Verbose("Assembly loaded {asm} to appdomain {domain} from\n{location}", args.LoadedAssembly.FullName, currentDomain.FriendlyName, args.LoadedAssembly.Location);
                };
                currentDomain.DomainUnload += delegate (object? sender, EventArgs e)
                {
                    log.Verbose("Domain {domain} unloaded", currentDomain.FriendlyName);
                };
            }
        }

        private static void CollectCache(this HttpServiceStack controller) => controller.Servers.TryForeach(static server => (server as HttpServer)!.CacheClear());
    }
}
