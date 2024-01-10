/*
* Copyright (c) 2024 Vaughn Nugent
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
using System.Reflection;
using System.Net.Security;
using System.Runtime.Loader;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Runtime.ExceptionServices;

using VNLib.Utils.IO;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Resources;
using VNLib.Utils.Extensions;
using VNLib.Utils.Memory.Diagnostics;
using VNLib.Hashing;
using VNLib.Hashing.Native.MonoCypher;
using VNLib.Net.Http;
using VNLib.Net.Transport.Tcp;
using VNLib.Plugins.Runtime;
using VNLib.Plugins.Essentials.ServiceStack;
using VNLib.Plugins.Essentials.ServiceStack.Construction;

using VNLib.WebServer.Plugins;
using VNLib.WebServer.Transport;
using VNLib.WebServer.Compression;
using VNLib.WebServer.Middlewares;
using VNLib.WebServer.TcpMemoryPool;
using VNLib.WebServer.RuntimeLoading;

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
        private const string SERVER_WHITELIST_PROP_NAME = "whitelist";

        private const string HTTP_CONF_PROP_NAME = "http";
        
        private const string HTTP_COMPRESSION_PROP_NAME = "compression_lib";

        private const string LOAD_DEFAULT_HOSTNAME_VALUE = "[system]";

        private const string PLUGINS_CONFIG_PROP_NAME = "plugins";


        static int Main(string[] args)
        {
            ProcessArguments procArgs = new(args);

            //Print the help menu
            if(args.Length == 0 || procArgs.HasArgument("-h") || procArgs.HasArgument("--help"))
            {
                PrintHelpMenu();
                return 0;
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
            if (procArgs.HasArgument("--dump-config"))
            {
                DumpConfig(config, logger);
            }

            //Setup the app-domain listener
            InitAppDomainListener(procArgs, logger.AppLog);

#if DEBUG
            if (procArgs.LogHttp)
            {
                logger.AppLog.Warn("HTTP Logging is only enabled in builds compiled with DEBUG symbols");
            }
#endif

            if (procArgs.ZeroAllocations && !MemoryUtil.Shared.CreationFlags.HasFlag(HeapCreation.GlobalZero))
            {
                logger.AppLog.Debug("Zero allocation flag was set, but the shared heap was not created with the GlobalZero flag, consider enabling zero allocations globally");
            }

            //get the http conf for all servers
            HttpConfig? http = GetHttpConfig(config, procArgs, logger);

            //If no http config is defined, we cannot continue
            if (!http.HasValue)
            {
                return -1;
            }

            logger.AppLog.Information("Building service stack, populating service domain...");

            //Init service stack with built-in http
            HttpServiceStackBuilder stack = new HttpServiceStackBuilder()
                                    .LoadPluginsConcurrently(!procArgs.HasArgument("--sequential-load"))
                                    .WithDomain(domain => LoadRoots(config, logger.AppLog, domain))
                                    .WithBuiltInHttp(sg => GetTransportForServiceGroup(sg, logger.SysLog, procArgs), http.Value);


            //Add plugins to the service stack
            ConfigurePlugins(stack, logger, procArgs, config);

            //Build the service stack
            using HttpServiceStack? serviceStack = stack.Build();

            if (serviceStack == null)
            {
                logger.AppLog.Error("Failed to build service stack, no virtual hosts were defined, exiting");
                return 0;
            }

            logger.AppLog.Information("Loading plugins...");

            //load plugins
            serviceStack.LoadPlugins(logger.AppLog);

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
            if (!procArgs.HasArgument("--input-off"))
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
@$"
    VNLib.Webserver Copyright (C) 2024 Vaughn Nugent

    A high-performance, cross-platform, single process, reference webserver built on the .NET 8.0 Core runtime.

    Option flags:
        --config         <path>     - Specifies the path to the configuration file (relative or absolute)
        --input-off                 - Disables the STDIN listener, no runtime commands will be processed
        --inline-scheduler          - Enables inline scheduling for TCP transport IO processing (not available when using TLS)
        --use-os-ciphers            - Overrides pre-configured TLS ciphers with OS provided ciphers
        --no-plugins                - Disables loading of dynamic plugins
        --log-http                  - Enables logging of HTTP request and response headers to the system logger (debug builds only)
        --log-transport             - Enables logging of transport events to the system logger (debug builds only)
        --dump-config               - Dumps the JSON configuration to the console during loading
        --compression-off           - Disables dynamic response compression
        --zero-alloc                - Forces all http/tcp memory pool allocations to be zeroed before use (reduced performance)
        --sequential-load           - Loads all plugins sequentially (default is concurrently)
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

    Optional environment variables:
        {MemoryUtil.SHARED_HEAP_FILE_PATH} - Specifies the path to the native heap allocator library
        {MemoryUtil.SHARED_HEAP_ENABLE_DIAGNOISTICS_ENV} - Enables heap diagnostics for the shared heap 1 = enabled, 0 = disabled
        {MemoryUtil.SHARED_HEAP_GLOBAL_ZERO} - Enables zeroing of all allocations from the shared heap 1 = enabled, 0 = disabled
        {MemoryUtil.SHARED_HEAP_RAW_FLAGS} - Raw flags to pass to the shared heap allocator's HeapCreate function, hexadeciaml encoded
        {VnArgon2.ARGON2_LIB_ENVIRONMENT_VAR_NAME} - Specifies the path to the Argon2 native library
        {MonoCypherLibrary.MONOCYPHER_LIB_ENVIRONMENT_VAR_NAME} - Specifies the path to the Monocypher native library

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
            string configPath = args.GetArgument("--config") ?? Path.Combine(EXE_DIR.FullName, DEFAULT_CONFIG_PATH);

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

        private static void ConfigurePlugins(HttpServiceStackBuilder http, ServerLogger logger, ProcessArguments args, JsonDocument config)
        {
            //do not load plugins if disabled
            if (args.HasArgument("--no-plugins"))
            {
                logger.AppLog.Information("Plugin loading disabled via options flag");
                return;
            }

            if (!config.RootElement.TryGetProperty(PLUGINS_CONFIG_PROP_NAME, out JsonElement plCfg))
            {
                logger.AppLog.Debug("No plugin configuration found");
                return;
            }

            //See if an alternate plugin config directory is specified
            string? altPluginConfigDir = plCfg.TryGetProperty("config_dir", out JsonElement cfgDirEl) ? cfgDirEl.GetString()! : null;

            //Check for hot-reload
            bool hotReload = plCfg.TryGetProperty("hot_reload", out JsonElement hrEl) && hrEl.GetBoolean();

            //Set the reload delay
            TimeSpan delay = TimeSpan.FromSeconds(2);
            if (plCfg.TryGetProperty("reload_delay_sec", out JsonElement reloadDelayEl))
            {
                delay = reloadDelayEl.GetTimeSpan(TimeParseType.Seconds);
            }

            string pluginDir = plCfg.TryGetProperty("path", out JsonElement pathEl) ? pathEl.GetString()! : "/plugins";

            //Init new plugin stack builder
            PluginStackBuilder pluginBuilder = PluginStackBuilder.Create()
                                    .WithDebugLog(logger.AppLog)
                                    .WithSearchDirectory(pluginDir)
                                    .WithLoaderFactory(pc => new PluginAssemblyLoader(pc));

            //Setup plugin config data
            if(string.IsNullOrWhiteSpace(altPluginConfigDir))
            {
                //Set config with root element
                pluginBuilder.WithLocalJsonConfig(config.RootElement);
            }
            else
            {
                //Specify alternate config directory
                pluginBuilder.WithJsonConfigDir(config.RootElement, new(altPluginConfigDir));
            }
            

            //Enable plugin hot-reload
            if (hotReload)
            {
                pluginBuilder.EnableHotReload(delay);
            }

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
                pluginDir,
                hotReload,
                delay.TotalSeconds
            );

            //Add the plugin stack to the http service stack
            http.WithPluginStack(pluginBuilder.ConfigureStack);
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
        private static bool LoadRoots(JsonDocument config, ILogProvider log, IDomainBuilder hosts)
        {
            try
            {
                //execution timeout
                TimeSpan execTimeout = config.RootElement.GetProperty(SESSION_TIMEOUT_PROP_NAME).GetTimeSpan(TimeParseType.Milliseconds);

                //Enumerate all virtual host configurations
                foreach (JsonElement rootEl in config.RootElement.GetProperty(HOSTS_CONFIG_PROP_NAME).EnumerateArray())
                {
                    //Inint config builder
                    VirtualHostConfigBuilder builder = new(rootEl, execTimeout);

                    //Get hostname array
                    string[] hostNames = builder.GetHostnameList();

                    //Get the configuration
                    VirtualHostConfig conf = builder.Build();

                    //Create directory if it doesnt exist yet
                    if (!conf.RootDir.Exists)
                    {
                        conf.RootDir.Create();
                    }

                    VirtualHostHooks hooks = new(conf);

                    //Init middleware stack
                    MainServerMiddlware main = new(log, conf);
                    SessionSecurityMiddelware sess = new(log);                    

                    //Create a new vritual host for every hostname using the same configuration
                    foreach(string hostName in hostNames)
                    {
                        //Substitute the dns hostname variable
                        string hn = hostName.Replace(LOAD_DEFAULT_HOSTNAME_VALUE, Dns.GetHostName(), StringComparison.OrdinalIgnoreCase);

                        //Configure new virtual host for each hostname
                       IVirtualHostBuilder vh = hosts.WithVirtualHost(conf.RootDir, hooks, log)
                            .WithHostname(hn)
                            .WithEndpoint(conf.TransportEndpoint)
                            .WithTlsCertificate(conf.Certificate)
                            .WithDefaultFiles(conf.DefaultFiles)
                            .WithExcludedExtensions(conf.ExcludedExtensions)
                            .WithAllowedAttributes(conf.AllowedAttributes)
                            .WithDisallowedAttributes(conf.DissallowedAttributes)
                            .WithDownstreamServers(conf.DownStreamServers)
                            .WithOption(p => p.ExecutionTimeout = conf.ExecutionTimeout)

                            //Add custom middleware
                            .WithMiddleware(main, sess);

                        /*
                         * We only enable cors if the configuration has a value for the allow cors property.
                         * The user may disable cors totally, deny cors requests, or enable cors with a whitelist
                         * 
                         * Only add the middleware if the confg has a value for the allow cors property
                         */
                        if (conf.AllowCors != null)
                        {
                            vh.WithMiddleware(new CORSMiddleware(log, conf));
                        }

                        //Add whitelist middleware if the configuration has a whitelist
                        if(conf.WhiteList != null)
                        {
                            vh.WithMiddleware(new WhitelistMiddleware(log, conf.WhiteList));
                        }
                    }

                    //Log the 
                    log.Information(
                        FOUND_VH_TEMPLATE,
                        hostNames,
                        conf.RootDir.FullName,
                        conf.TransportEndpoint,
                        conf.Certificate != null,
                        conf.Certificate.IsClientCertRequired(),
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

                IHttpCompressorManager? compressorManager = LoadOrDefaultCompressor(args, config, logger);

                HttpConfig conf = new(logger.SysLog, PoolManager.GetHttpPool(args.ZeroAllocations))
                {
                    RequestDebugLog = args.LogHttp ? logger.AppLog : null,
                    DefaultHttpVersion = HttpHelpers.ParseHttpVersion(httpEl["default_version"].GetString()),
                    MaxUploadSize = httpEl["max_entity_size"].GetInt64(),
                    CompressionLimit = (int)httpEl["compression_limit"].GetUInt32(),
                    CompressionMinimum = (int)httpEl["compression_minimum"].GetUInt32(),
                    MaxFormDataUploadSize = (int)httpEl["multipart_max_size"].GetUInt32(),
                    ConnectionKeepAlive = httpEl["keepalive_ms"].GetTimeSpan(TimeParseType.Milliseconds),
                    ActiveConnectionRecvTimeout = (int)httpEl["recv_timeout_ms"].GetUInt32(),
                    SendTimeout = (int)httpEl["send_timeout_ms"].GetUInt32(),
                    MaxRequestHeaderCount = (int)httpEl["max_request_header_count"].GetUInt32(),
                    MaxOpenConnections = (int)httpEl["max_connections"].GetUInt32(),     
                    MaxUploadsPerRequest = httpEl["max_uploads_per_request"].GetUInt16(),

                    //Buffer config update
                    BufferConfig = new()
                    {
                        RequestHeaderBufferSize = httpEl["header_buf_size"].GetInt32(),
                        ResponseHeaderBufferSize = httpEl["response_header_buf_size"].GetInt32(),
                        FormDataBufferSize = httpEl["multipart_max_buf_size"].GetInt32(),
                        ResponseBufferSize = httpEl["response_buf_size"].GetInt32(),

                        //Only set chunk buffer size if compression is enabled
                        ChunkedResponseAccumulatorSize = compressorManager != null ? CHUNCKED_ACC_BUFFER_SIZE : 0
                    },

                    HttpEncoding = Encoding.ASCII,

                    //Init compressor
                    CompressorManager = compressorManager
                };
                return conf.DefaultHttpVersion == Net.Http.HttpVersion.None
                    ? throw new ServerConfigurationException("Your default HTTP version is invalid, specify an RFC formatted http version 'HTTP/x.x'")
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

        private delegate void OnHttpLibLoad(ILogProvider log, JsonElement? configData);

        private static IHttpCompressorManager? LoadOrDefaultCompressor(ProcessArguments args, JsonDocument config, ServerLogger logger)
        {
            const string EXTERN_LIB_LOAD_METHOD_NAME = "OnLoad";

            if (args.HasArgument("--compression-off"))
            {
                logger.AppLog.Debug("Compression disabled by cli args");
                return null;
            }

            //Try to get the compressor assembly file from config
            if (!config.RootElement.TryGetProperty(HTTP_COMPRESSION_PROP_NAME, out JsonElement compAsmEl))
            {
                logger.AppLog.Debug("Falling back to default http compressor");
                return new FallbackCompressionManager();
            }

            //Try to get the compressor assembly file from config
            string? compAsmPath = compAsmEl.GetString();

            if (string.IsNullOrWhiteSpace(compAsmPath))
            {
                logger.AppLog.Debug("Falling back to default http compressor");
                return new FallbackCompressionManager();
            }

            //Make sure the file exists
            if (!FileOperations.FileExists(compAsmPath))
            {
                logger.AppLog.Warn("The specified http compressor assembly file does not exist, falling back to default http compressor");
                return new FallbackCompressionManager();
            }

            //Try to load the assembly into our alc, we dont need to worry about unloading
            ManagedLibrary lib = ManagedLibrary.LoadManagedAssembly(compAsmPath, AssemblyLoadContext.Default);

            logger.AppLog.Debug("Loading user defined compressor assembly\n{asm}", lib.AssemblyPath);

            try
            {
                //Load the compressor manager type from the assembly
                IHttpCompressorManager instance = lib.LoadTypeFromAssembly<IHttpCompressorManager>();

                /*
                 * We can provide some optional library initialization functions if the library 
                 * supports it. First we can allow the library to write logs to our log provider
                 * and second we can provide the library with the raw configuration data as a byte array
                 */

                //Invoke the on load method with the logger and config data
                OnHttpLibLoad? onlibLoadConfig = ManagedLibrary.TryGetMethod<OnHttpLibLoad>(instance, EXTERN_LIB_LOAD_METHOD_NAME);
                onlibLoadConfig?.Invoke(logger.AppLog, config.RootElement);

                //Invoke parameterless on load method
                Action? onLibLoad = ManagedLibrary.TryGetMethod<Action>(instance, EXTERN_LIB_LOAD_METHOD_NAME);
                onLibLoad?.Invoke();

                return instance;
            }
            //Catch TIE and throw the inner exception for cleaner debug
            catch(TargetInvocationException te) when (te.InnerException != null)
            {
                throw te.InnerException;
            }
        }

        private static ITransportProvider GetTransportForServiceGroup(ServiceGroup group, ILogProvider sysLog, ProcessArguments args)
        {
            SslServerAuthenticationOptions? sslAuthOptions = null;

            //See if certs are defined
            if (group.Hosts.Where(static h => h.TransportInfo.Certificate != null).Any())
            {
                //If any hosts have ssl enabled, all shared endpoints MUST include a certificate to be bound to the same endpoint
                if(!group.Hosts.All(static h => h.TransportInfo.Certificate != null))
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

                DebugTcpLog = args.HasArgument("--log-transport"),

                //Init buffer pool
                BufferPool = PoolManager.GetPool(args.ZeroAllocations)
            };

            //Print warning message, since inline scheduler is an avanced feature
            if(sslAuthOptions is not null && inlineScheduler)
            {
                sysLog.Debug("[WARN]: Inline scheduler is not available on server {server} when using TLS", group.ServiceEndpoint);
            }

            //Init new tcp server with/without ssl
            return sslAuthOptions != null ? 
                TcpTransport.CreateServer(in tcpConf, sslAuthOptions) 
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
                switch (s[0].ToLower(null))
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
