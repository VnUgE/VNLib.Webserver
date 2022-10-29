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
using System.Security.Authentication;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography.X509Certificates;

using Serilog;

using VNLib.Utils.IO;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Net.Http;
using VNLib.Net.Transport.Tcp;
using VNLib.Plugins;
using VNLib.Plugins.Runtime;
using VNLib.Plugins.Essentials.Content;
using VNLib.Plugins.Essentials.Sessions;
using HttpVersion = VNLib.Net.Http.HttpVersion;

using VNLib.WebServer.Transport;
using VNLib.WebServer.TcpMemoryPool;
/*
* Arguments
* --config <config_path>
* -v --verbose
* -d --debug
* -vv double verbose mode (logs all app-domain events)
* -s --silent silent logging mode, does not print logs to the console, only to output files
* --log-http prints raw http requests to the application log
* --rpmalloc to force enable the rpmalloc library loading for the Memory class
*/

#nullable enable

namespace VNLib.WebServer
{
    static class Entry
    {
        const string STARTUP_MESSAGE =
@"VNLib Copyright (C) 2022 Vaughn Nugent
This program comes with ABSOLUTELY NO WARRANTY.
Licensing for this software and other libraries can be found at https://www.vaughnnugent.com/resources/vnlib
Starting...
";


        private static readonly DirectoryInfo EXE_DIR = new(Environment.CurrentDirectory);
        private static readonly IPEndPoint DefaultInterface = new(IPAddress.Any, 80);
        private static readonly Regex DefaultRootRegex = new(@"(\/\.\.)|(\\\.\.)|[\[\]^*<>|`~'\n\r\t\n]|(\s$)|^(\s)", RegexOptions.Compiled);

        private static readonly TCPConfig BaseTcpConfig = new()
        {
            AcceptThreads = 24 * 2,
            KeepaliveInterval = 4,
            TcpKeepalive = false,
            TcpKeepAliveTime = 4,
            CacheQuota = 0,
            //Allow 100k per connection to be pre-loaded
            MaxRecvBufferData = 64 * 1024,
            BackLog = 1000
        };

        private static readonly List<SslApplicationProtocol> SslAppProtocols = new()
        {
            SslApplicationProtocol.Http11,
            //SslApplicationProtocol.Http2,
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

        private const string LOAD_DEFAULT_HOSTNAME_VALUE = "[system]";
       

        static int Main(string[] args)
        {
            //Set the RPMalloc env var for the process
            if (args.Contains("--rpmalloc"))
            {
                //Set initial env to use the rpmalloc allocator for the default heaps
                Environment.SetEnvironmentVariable(Memory.SHARED_HEAP_TYPE_ENV, "rpmalloc", EnvironmentVariableTarget.Process);
            }

            Console.WriteLine(STARTUP_MESSAGE);

            //Setup logger configs
            LoggerConfiguration sysLogConfig = new();
            LoggerConfiguration appLogConfig = new();
            //Check log verbosity level and configure logger minimum levels
            InitConsoleLog(args, sysLogConfig, "System");
            InitConsoleLog(args, appLogConfig, "Application");
            //try to load the json configuration file
            using JsonDocument? config = LoadConfig(args);
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
            ApplicationLog.Information("Loading virtual hosts");
            //Get web roots
            List<VirtualHost> allHosts = new();
            if (!LoadRoots(config, ApplicationLog, allHosts))
            {
                ApplicationLog.Error("No virtual hosts were defined, exiting");
                return 0;
            }
            //Get new server list
            List<HttpServer> servers = new();
            //Load non-ssl servers
            InitServers(servers, allHosts, SystemLog, http.Value);
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
            LoadPlugins(plugins, config, ApplicationLog, allHosts);
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
            Console.CancelKeyPress += (object? sender, ConsoleCancelEventArgs e) =>
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

            ApplicationLog.Verbose("Main thread waiting for exit signal");
                
            //Wait for process cleanup/exit
            ShutdownEvent.Wait();

            ApplicationLog.Information("Stopping server");
            //Stop all services 
            cancelSource.Cancel();
            //Wait for all plugins to unload and cleanup (temporary)
            Thread.Sleep(500);
            return 0;
        }

        #region config
        /// <summary>
        /// Initializes the configuration DOM from the specified cmd args 
        /// or the default configuration path
        /// </summary>
        /// <param name="args">The command-line-arguments</param>
        /// <returns>A new <see cref="JsonDocument"/> that contains the application configuration</returns>
        private static JsonDocument? LoadConfig(string[] args)
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
            //Allow comments
            JsonDocumentOptions jdo = new()
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            };
            return JsonDocument.Parse(fs, jdo);
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
            
            TimeSpan flushInterval = TimeSpan.FromSeconds(2);
            int retainedLogs = 31;
            //Default to 500mb log file size
            int fileSizeLimit = 500 * 1000 * 1024;
            RollingInterval interval = RollingInterval.Infinite;

            //try to get the log config object
            if (config.RootElement.TryGetProperty(elPath, out JsonElement logEl))
            {
                IReadOnlyDictionary<string, JsonElement> conf = logEl.EnumerateObject().ToDictionary(s => s.Name, s => s.Value);

                filePath = conf.GetPropString("path");
                template = conf.GetPropString("template");

                if (conf.TryGetValue("flush_sec", out JsonElement flushEl))
                {
                    flushInterval = flushEl.GetTimeSpan(TimeParseType.Seconds);
                }

                if (conf.TryGetValue("retained_files", out JsonElement retainedEl))
                {
                    retainedLogs = retainedEl.GetInt32();
                }

                if (conf.TryGetValue("file_size_limit", out JsonElement sizeEl))
                {
                    fileSizeLimit = sizeEl.GetInt32();
                }

                if (conf.TryGetValue("interval", out JsonElement intervalEl))
                {
                    interval = Enum.Parse<RollingInterval>(intervalEl.GetString()!, true);
                }
            }
            //Set default objects
            filePath ??= Path.Combine(Environment.CurrentDirectory, $"{elPath}.txt");
            template ??= $"{{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz}} [{{Level:u3}}] {logName} {{Message:lj}}{{NewLine}}{{Exception}}";
            //Configure the log file writer
            logConfig.WriteTo.File(filePath, buffered: true, retainedFileCountLimit:retainedLogs, fileSizeLimitBytes:fileSizeLimit, rollingInterval:interval, outputTemplate: template);
        }
        
        #endregion
       
        /// <summary>
        /// Loads all server roots from the configuration file
        /// </summary>
        /// <param name="config">The application configuration to load</param>
        /// <param name="log"></param>
        /// <remarks>A value that indicates if roots we loaded correctly, or false if errors occured and could not be loaded</remarks>
        private static bool LoadRoots(JsonDocument config, ILogProvider log, ICollection<VirtualHost> hosts)
        {
            try
            {
                //Enumerate all virtual hosts
                foreach (JsonElement rootEl in config.RootElement.GetProperty(HOSTS_CONFIG_PROP_NAME).EnumerateArray())
                {
                    //Get root config as dict
                    IReadOnlyDictionary<string, JsonElement> rootConf = rootEl.EnumerateObject().ToDictionary(static kv => kv.Name, static kv => kv.Value);

                    //Get the hostname and path of the root
                    string? hostname = rootConf[SERVER_HOSTNAME_PROP_NAME].GetString();
                    string? rootPath = rootConf[SERVER_ROOT_PATH_PROP_NAME].GetString();
                    //Default hostname setup
                    {
                        //If the hostname value is exactly the matching path, then replace it for the dns hostname
                        hostname = hostname?.Replace(LOAD_DEFAULT_HOSTNAME_VALUE, Dns.GetHostName());
                    }
                    //Setup a default service interface
                    IPEndPoint serverEndpoint = DefaultInterface;
                    {
                        //Get the interface binding for this host
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
                    VirtualHost root = new(rootPath, hostname, log, (int) timeoutMs)
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
                    hosts.Add(root);
                    log.Information("Found virtual host {ep} on {if}, with TLS {tls}, upstream servers {us}", hostname, serverEndpoint, cert != null, upstreamServers);
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
                    CompressionMinimum = httpEl["compression_minimum"].GetInt32(),
                    DefaultHttpVersion = HttpHelpers.ParseHttpVersion(httpEl["default_version"].GetString()),
                    FormDataBufferSize = httpEl["multipart_max_buffer"].GetInt32(),
                    MaxFormDataUploadSize = httpEl["multipart_max_size"].GetInt32(),
                    MaxUploadSize = httpEl["max_entity_size"].GetInt32(),
                    TransportKeepalive = httpEl["keepalive_ms"].GetTimeSpan(TimeParseType.Milliseconds),
                    HeaderBufferSize = httpEl["header_buf_size"].GetInt32(),
                    ActiveConnectionRecvTimeout = httpEl["recv_timout_ms"].GetInt32(),
                    MaxRequestHeaderCount = httpEl["max_request_header_count"].GetInt32(),
                    MaxOpenConnections = httpEl["max_connections"].GetInt32(),
                    ResponseBufferSize = httpEl["response_buf_size"].GetInt32(),
                    ResponseHeaderBufferSize = httpEl["response_header_buf_size"].GetInt32(),
                    DiscardBufferSize = httpEl["request_discard_buf_size"].GetInt32(),
                    ChunkedResponseAccumulatorSize = 64 * 1024,

                    HttpEncoding = Encoding.ASCII,
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
        private static void InitServers(List<HttpServer> servers, IEnumerable<VirtualHost> roots, ILogProvider sysLog, in HttpConfig httpConf)
        {
            //Get a distinct list of the server interfaces that are required to setup hosts
            IEnumerable<IPEndPoint> interfaces = (from root in roots select root.ServerEndpoint).Distinct();
            foreach (IPEndPoint serverEp in interfaces)
            {
                SslServerAuthenticationOptions? sslAuthOptions = null;
                //get all roots that use the same Ip/port
                IEnumerable<VirtualHost> rootsForEp = (from root in roots where root.ServerEndpoint.Equals(serverEp) select root);
                //Get all roots for the specified endpoints that have certificates
                IEnumerable<VirtualHost> sslRoots = (from root in rootsForEp where root.Certificate != null select root);
                //See if any ssl roots are configured
                if (sslRoots.Any())
                {
                    
                    
                    //Setup a cert lookup for all roots that defined certs
                    IReadOnlyDictionary<string, X509Certificate?> certLookup = sslRoots.ToDictionary(root => root.Hostname, root => root.Certificate)!;
                    //If the wildcard hostname is set save a local copy
                    X509Certificate? defaultCert = certLookup.GetValueOrDefault("*", null);
                    //Build the server auth options
                    sslAuthOptions = new()
                    {
                        //Local callback for cert selection
                        ServerCertificateSelectionCallback = delegate (object sender, string? hostName)
                        {
                            // use the default cert if the hostname is not specified
                            return certLookup.GetValueOrDefault(hostName!, defaultCert)!;
                        },
                        EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        RemoteCertificateValidationCallback = delegate (object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
                        {
                            return true;
                        },
                        ApplicationProtocols = SslAppProtocols,
                        AllowRenegotiation = false,
                    };
                }
                //Init a new TCP config
                TCPConfig tcpConf = new()
                {
                    LocalEndPoint = serverEp,
                    Log = sysLog,
                    AuthenticationOptions = sslAuthOptions,
                    //Copy from base config
                    AcceptThreads = BaseTcpConfig.AcceptThreads,
                    TcpKeepAliveTime = BaseTcpConfig.TcpKeepAliveTime,
                    KeepaliveInterval = BaseTcpConfig.KeepaliveInterval,
                    TcpKeepalive = BaseTcpConfig.TcpKeepalive,
                    CacheQuota = BaseTcpConfig.CacheQuota,
                    MaxRecvBufferData = BaseTcpConfig.MaxRecvBufferData,
                    BackLog = BaseTcpConfig.BackLog,
                    //Init buffer pool
                    BufferPool = PoolManager.GetPool<byte>()
                };
                //Init new tcp server
                TcpTransportProvider tcp = new(tcpConf);
                //Create the new server
                HttpServer server = new(httpConf, tcp, rootsForEp);
                //Add the server to the list
                servers.Add(server);
            }
        }

        #region Plugins

        static readonly string PluginFileExtension = OperatingSystem.IsWindows() ? ".dll" : ".so";

        private static void LoadPlugins(List<WebPluginLoader> plugins, JsonDocument config, ILogProvider appLog, IEnumerable<VirtualHost> hosts)
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
            IEnumerable<string> pluginPaths = dirs.Where(static pdir =>
            {
                string compined = Path.Combine(pdir.FullName, pdir.Name);
                string FilePath = string.Concat(compined, PluginFileExtension);
                return FileOperations.FileExists(FilePath);
            })
            //Return the name of the dll file to import
            .Select(static pdir =>
            {
                string compined = Path.Combine(pdir.FullName, pdir.Name);
                return string.Concat(compined, PluginFileExtension);
            });
            List<Task> loading = new();
            foreach (string pluginPath in pluginPaths)
            {
                appLog.Verbose("Found plugin file {file}", Path.GetFileName(pluginPath));

                async Task Load()
                {
                    WebPluginLoader plugin = new(pluginPath, config, appLog, hotReload, hotReload);
                    try
                    {
                        await plugin.InitLoaderAsync();
                        //Load all endpoints
                        plugin.LoadEndpoints(hosts);
                        //Listen for reload events to remove and re-add endpoints
                        plugin.Reloaded += delegate (object? sender, List<LivePlugin> lp)
                        {
                            WebPluginLoader wpl = (sender as WebPluginLoader)!;
                            wpl.LoadEndpoints(hosts);
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
            appLog.Verbose("Waiting for enabled plugins to load");
            //wait for loading to completed
            Task.WaitAll(loading.ToArray());

            appLog.Verbose("Plugins loaded");
            
            {
                //get the loader that contains the single session provider
                WebPluginLoader? sessionLoader = (from pp in plugins
                                                 where pp.GetLoaderForSingleType<ISessionProvider>() != null
                                                 select pp)
                                                .SingleOrDefault();
                //Method to load sessions to all roots
                static void LoadSessions(IEnumerable<VirtualHost> roots, ISessionProvider provider)
                {
                    foreach (VirtualHost root in roots)
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
                        LoadSessions(hosts, loaded);
                    });
                    //Load sessions
                    LoadSessions(hosts, sp);
                }
            }
            //Loader for the page router
            {
                static void LoadRouter(IEnumerable<VirtualHost> roots, IPageRouter router)
                {
                    foreach (VirtualHost root in roots)
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
                        LoadRouter(hosts, newRouter);
                    });
                    //Load the current router
                    LoadRouter(hosts, router);
                }
            }
        }


        internal static void LoadEndpoints(this WebPluginLoader loader, IEnumerable<VirtualHost> roots)
        {
            //Get endpoints for current loader
            IEndpoint[] eps = loader.GetEndpoints().ToArray();
            //Loop through hosts
            foreach(VirtualHost root in roots)
            {
                //Remove endpoints
                root.RemoveEndpoint(eps);
                //Re-add endpoints
                root.AddEndpoint(eps);
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
                log.Verbose("Double verbose mode enabled, registering app-domain listeners");
                    
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
