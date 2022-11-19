/*
* Copyright (c) 2022 Vaughn Nugent
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
using System.Security.Authentication;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography.X509Certificates;

using VNLib.Utils.IO;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Net.Http;
using VNLib.Plugins.Essentials.ServiceStack;

using VNLib.WebServer.Transport;
using VNLib.WebServer.TcpMemoryPool;
using VNLib.WebServer.RuntimeLoading;
using VNLib.Net.Transport.Tcp;

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


namespace VNLib.WebServer
{
    static class Entry
    {
        const string STARTUP_MESSAGE =
@"VNLib Copyright (C) Vaughn Nugent
This program comes with ABSOLUTELY NO WARRANTY.
Licensing for this software and other libraries can be found at https://www.vaughnnugent.com/resources/vnlib
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
        private const string DOWNSTREAM_TRUSTED_SERVERS_PROP = "downstream_servers";

        private const string HTTP_CONF_PROP_NAME = "http";

        private const string SERVER_WHITELIST_PROP_NAME = "whitelist";

        private const string LOAD_DEFAULT_HOSTNAME_VALUE = "[system]";
       

        static int Main(string[] args)
        {
            ProcessArguments procArgs = new(args);

            //Set the RPMalloc env var for the process
            if (procArgs.RpMalloc)
            {
                //Set initial env to use the rpmalloc allocator for the default heaps
                Environment.SetEnvironmentVariable(Memory.SHARED_HEAP_TYPE_ENV, "rpmalloc", EnvironmentVariableTarget.Process);
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
            
            using ManualResetEventSlim ShutdownEvent = new(false);
            
            //Start listening for commands on a background thread, so it does not interfere with async tasks on tp threads
            Thread consoleListener = new(() => StdInListenerDoWork(ShutdownEvent, logger.AppLog, serviceStack))
            {
                //Allow the main thread to exit
                IsBackground = true
            };
            
            //Start listener thread
            consoleListener.Start();

            logger.AppLog.Verbose("Main thread waiting for exit signal");
                
            //Wait for process cleanup/exit
            ShutdownEvent.Wait();

            logger.AppLog.Information("Stopping service stack");

            //Wait for ss to exit
            serviceStack.StopAndWaitAsync().Wait();
          
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

        #endregion

        public static HttpServiceStack? BuildStack(ServerLogger logger, ProcessArguments args, in HttpConfig httpConfig, JsonDocument config)
        {
            //Init service stack
            HttpServiceStack serviceStack = new();
            try
            {
                //Build the service domain from roots
                bool built = serviceStack.ServiceDomain.BuildDomain(collection => LoadRoots(config, logger.AppLog, collection));

                //Make sure a service stack was loaded
                if (!built)
                {
                    return null;
                }

                //Wait for plugins to load
                serviceStack.ServiceDomain.LoadPlugins(config, logger.AppLog).Wait();

                //Build servers
                serviceStack.BuildServers(in httpConfig, group => GetTransportForServiceGroup(group, logger.SysLog, args));
            }
            catch
            {
                serviceStack.Dispose();
                throw;
            }
            return serviceStack;
        }

        private const string FOUND_VH_TEMPLATE =
@"
--------------------------------------------------
 |           Found virtual host:
 | hostname: {hn}
 | Listening on: {ep}
 | SSL: {ssl}
 | Whitelist entries: {wl}
 | Downstream servers {ds}
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
                                                                                              f.GetProperty("path").GetString()!)));
                            ff = new(ffs);
                        }
                        else
                        {
                            ff = new();
                        }
                    }
                    //Find downstream servers
                    HashSet<IPAddress> downstreamServers = new();
                    {
                        //See if element is set
                        if (rootConf.TryGetValue(DOWNSTREAM_TRUSTED_SERVERS_PROP, out JsonElement downstreamEl))
                        {
                            //hash endpoints 
                            downstreamServers = downstreamEl.EnumerateArray().Select(static addr => IPAddress.Parse(addr.GetString()!)).ToHashSet();
                        }
                    }
                    //Check Whitelist
                    HashSet<IPAddress>? whiteList = null;
                    {
                        //See if whitelist is defined
                        if(rootConf.TryGetValue(SERVER_WHITELIST_PROP_NAME, out JsonElement wlEl))
                        {
                            whiteList = wlEl.EnumerateArray().Select(static addr => IPAddress.Parse(addr.GetString()!)).ToHashSet();
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
                    
                    //Create a new server root 
                    VirtualHost root = new(rootPath, hostname, log)
                    {
                        //Configure ep options
                        VirtualHostOptions = new EPOptionsImpl()
                        {
                            AllowCors = rootConf.TryGetValue(SERVER_CORS_ENEABLE_PROP_NAME, out JsonElement corsEl) && corsEl.GetBoolean(),
                            
                            //Set optional whitelist
                            WhiteList = whiteList,
                            
                            //Set required downstream servers
                            DownStreamServers = downstreamServers,
                            ExcludedExtensions = excludedExtensions,
                            DefaultFiles = defaultFiles,
                            
                            //store certificate
                            Certificate = cert,
                            //Set inerface
                            TransportEndpoint = serverEndpoint,
                            PathFilter = pathFilter,
                            
                            //Get optional security config options
                            RefererPolicy = rootConf.GetPropString(SERVER_REFER_POLICY_PROP_NAME),                           
                            HSTSHeader = rootConf.GetPropString(SERVER_HSTS_HEADER_PROP_NAME),
                            ContentSecurityPolicy = rootConf.GetPropString(SERVER_CONTENT_SEC_PROP_NAME),                            

                            CacheDefault = rootConf[SERVER_CACHE_DEFAULT_PROP_NAME].GetTimeSpan(TimeParseType.Seconds),
                            
                            //execution timeout
                            ExecutionTimeout = config.RootElement.GetProperty(SESSION_TIMEOUT_PROP_NAME).GetTimeSpan(TimeParseType.Milliseconds)
                        },
                        FailureFiles = new(ff),
                    };
                    //Add root to the list
                    hosts.Add(root);
                    log.Information(FOUND_VH_TEMPLATE, hostname, serverEndpoint, cert != null, whiteList, downstreamServers);
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
        private static HttpConfig? GetHttpConfig(JsonDocument config, ProcessArguments args, ServerLogger logger)
        {
            try
            {
                //Get the http element
                IReadOnlyDictionary<string, JsonElement> httpEl = config.RootElement.GetProperty(HTTP_CONF_PROP_NAME)
                                                                            .EnumerateObject()
                                                                            .ToDictionary(static k => k.Name, static v => v.Value);
                HttpConfig conf = new(logger.SysLog)
                {
                    RequestDebugLog = args.LogHttp ? logger.AppLog : null,
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
                return conf.DefaultHttpVersion == Net.Http.HttpVersion.NotSupported
                    ? throw new Exception("default_version is invalid, specify an RFC formatted http version 'HTTP/x.x'")
                    : conf;
            }
            catch (KeyNotFoundException kne)
            {
                logger.AppLog.Error("Missing required HTTP configuration varaibles {var}", kne.Message);
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
                //Init ssl options

                //Setup a cert lookup for all roots that defined certs
                IReadOnlyDictionary<string, X509Certificate?> certLookup = group.Hosts.ToDictionary(root => root.Processor.Hostname, root => root.TransportInfo.Certificate)!;
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

            //Check cli args thread count
            string? procCount = args.GetArg("-t");
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
                
                //Optional ssl options
                AuthenticationOptions = sslAuthOptions,

                //Copy from base config
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
            return new TcpTransportProvider(tcpConf);
        }

        private static void StdInListenerDoWork(ManualResetEventSlim shutdownEvent, ILogProvider appLog, HttpServiceStack serviceStack)
        {
            //Register console cancel to cause cleanup
            Console.CancelKeyPress += (object? sender, ConsoleCancelEventArgs e) =>
            {
                e.Cancel = true;
                shutdownEvent.Set();
            };

            while (!shutdownEvent.IsSet)
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

                            bool sent = serviceStack.ServiceDomain.SendCommandToPlugin(s[1], message);

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
                                serviceStack.ServiceDomain.ForceReloadAllPlugins();
                            }
                            catch (Exception ex)
                            {
                                appLog.Error(ex);
                            }
                        }
                        break;
                    case "stats":
                        {
                            int gen0 = GC.CollectionCount(0);
                            int gen1 = GC.CollectionCount(1);
                            int gen2 = GC.CollectionCount(2);
                            appLog.Debug("Collection Gen0 {gen0} Gen1 {gen1} Gen2 {gen2}", gen0, gen1, gen2);
                            GCMemoryInfo mi = GC.GetGCMemoryInfo();
                            appLog.Debug("Compacted {cp} Last Size {lz}kb, Pause % {pa}", mi.Compacted, mi.HeapSizeBytes / 1024, mi.PauseTimePercentage);
                            appLog.Debug("High watermark {hw}kb Current Load {cc}kb", mi.HighMemoryLoadThresholdBytes / 1024, mi.MemoryLoadBytes / 1024);
                            appLog.Debug("Fargmented kb {frag} Concurrent {cc}", mi.FragmentedBytes / 1024, mi.Concurrent);
                            appLog.Debug("Pending finalizers {pf} Pinned Objects {pinned}", mi.FinalizationPendingCount, mi.PinnedObjectsCount);
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

        private static void CollectCache(this HttpServiceStack controller) => controller.Servers.TryForeach(static server => server.CacheClear());
    }
}
