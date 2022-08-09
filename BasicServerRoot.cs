using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Collections.ObjectModel;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using VNLib.Net;
using VNLib.Net.Http;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials;
using VNLib.Plugins.Essentials.Extensions;

#nullable enable

namespace VNLib.WebServer
{
    internal sealed class BasicServerRoot : EventProcessor
    {
        private const int FILE_PATH_BUILDER_BUFFER_SIZE = 4096;

        internal readonly DirectoryInfo Root;      
        public ReadOnlyCollection<string> defaultFiles { get; init; }        
        public HashSet<string> excludedExtensions { get; init; }
        /// <summary>
        /// A collection of trusted upstream servers
        /// </summary>
        public IReadOnlySet<IPAddress> upstreamServers { get; init; }
        /// <summary>
        /// A per-root value that defines if CORS is enabled for all connections to this site
        /// </summary>
        internal bool allowCors { get; init; }

        /// <summary>
        /// The current sites Content-Secruity-Policy header value
        /// </summary>
        public string? ContentSecurityPolicy { get; init; }
        /// <summary>
        /// The TLS certificate to use for this website
        /// </summary>
        public X509Certificate? Certificate { get; init; }
        /// <summary>
        /// The IP endpoint of the server that should serve this root
        /// </summary>
        public IPEndPoint ServerEndpoint { get; init; }
        /// <summary>
        /// A regex filter instance to filter incoming filesystem paths
        /// </summary>
        public Regex PathFilter { get; init; }
        /// <summary>
        /// Strict transport security header
        /// </summary>
        public string? HSTSHeader { get; init; }
        /// <summary>
        /// An optional whitelist set of ipaddresses that are allowed to make connections to this site
        /// </summary>
        public IReadOnlySet<IPAddress>? WhiteList { get; init; }
        /// <summary>
        /// Sets the site's referrer policy header
        /// </summary>
        public string RefererPolicy { get; init; }
        /// <summary>
        /// The default response entity cache value
        /// </summary>
        public TimeSpan CacheDefault { get; init; }       
        public ReadOnlyDictionary<HttpStatusCode, FailureFile> FailureFiles { get; init; }

        ///<inheritdoc/>
        public override bool AllowCors { get => allowCors; }
        ///<inheritdoc/>
        public override string Hostname { get; }
        ///<inheritdoc/>
        public override string Directory => Root.FullName;
        ///<inheritdoc/>
        public override TimeSpan OperationTimeout { get; }
        ///<inheritdoc/>
        public override IReadOnlyCollection<string> DefaultFiles => defaultFiles;
        ///<inheritdoc/>
        public override IReadOnlySet<string> ExcludedExtensions => excludedExtensions;
        ///<inheritdoc/>
        public override FileAttributes AllowedAttributes => FileAttributes.Archive | FileAttributes.Compressed | FileAttributes.Normal | FileAttributes.ReadOnly;
        ///<inheritdoc/>
        public override FileAttributes DissallowedAttributes => 
            FileAttributes.Device 
            | FileAttributes.Directory 
            | FileAttributes.Encrypted 
            | FileAttributes.Hidden 
            | FileAttributes.IntegrityStream 
            | FileAttributes.Offline 
            | FileAttributes.ReparsePoint 
            | FileAttributes.System;
        
        ///<inheritdoc/>
        public override IReadOnlySet<IPAddress> UpstreamServers => upstreamServers;
#nullable disable
        public BasicServerRoot(string path, string hostName, ILogProvider log, int timeoutMs) : base(log)
        {
            Root = new DirectoryInfo(path);
            if (!Root.Exists)
            {
                Root.Create();
            }
            Hostname = hostName;
            OperationTimeout = TimeSpan.FromMilliseconds(timeoutMs);
            //Inint default cache string
            DefaultCacheString = new(() => HttpHelpers.GetCacheString(CacheType.Public, (int)CacheDefault.TotalSeconds), false);
        }
#nullable enable

        public override bool ErrorHandler(HttpStatusCode errorCode, HttpEvent ev)
        {
            //Make sure the connection accepts html
            if (ev.Server.Accepts(ContentType.Html) && FailureFiles.TryGetValue(errorCode, out FailureFile? ff))
            {
                ev.Server.SetCache(CacheType.NoCache | CacheType.NoStore, TimeSpan.Zero);
                ev.CloseResponse(errorCode, ContentType.Html, ff.File);
                return true;
            }
            return false;
        }

        public override string TranslateResourcePath(string requestPath)
        {
            //Filter the path using the supplied regex
            requestPath = PathFilter.Replace(requestPath, string.Empty);
            //Alloc temp buffer from the shared heap, 
            using UnsafeMemoryHandle<char> charBuffer = Memory.UnsafeAlloc<char>(FILE_PATH_BUILDER_BUFFER_SIZE);
            //Buffer writer
            VnBufferWriter<char> sb = new(charBuffer.Span);
            //Start with the root filename
            sb.Append(Root.FullName);
            //Supply a "leading" dir separator character 
            if (requestPath[0] != '/')
            {
                sb.Append('/');
            }
            //Add the path (trimmed for whitespace)
            sb.Append(requestPath);
            //Attmept to filter traversals
            sb.Replace("..", string.Empty);
            //if were on windows, convert to windows directory separators
            if (OperatingSystem.IsWindows())
            {
                sb.Replace("/", "\\");
            }
            //Convert to unix paths
            else
            {
                sb.Replace("\\", "/");
            }
            //If file is given without extension, append a .html extension
            if (!Path.EndsInDirectorySeparator(requestPath) && !Path.HasExtension(requestPath))
            {
                sb.Append(".html");
            }
            return sb.ToString();
        }

        public override FileProcessArgs PreProcessEntity(in HttpEntity entity)
        {
            //Block websocket requests
            if (entity.Server.IsWebSocketRequest)
            {
                Log.Verbose("Client {ip} made a websocket request", entity.TrustedRemoteIp);
            }
            //If a whitelist has been defined, block requests from non-whitelisted IPs
            if (WhiteList != null && !WhiteList.Contains(entity.TrustedRemoteIp))
            {
                Log.Verbose("Client {ip} is not whitelisted, blocked", entity.TrustedRemoteIp);
                return FileProcessArgs.Deny;
            }
            if (!entity.Session.IsSet || !entity.Server.IsBrowser())
            {
                return FileProcessArgs.Continue;
            }
            /*
             * Check if the session was established over a secure connection, 
             * and if the current connection is insecure, redirect them to a 
             * secure connection.
             */
            if (entity.Session.SecurityProcol > SslProtocols.None && !entity.Server.IsSecure)
            {
                //Redirect the client to https
                UriBuilder ub = new(entity.Server.RequestUri)
                {
                    Scheme = Uri.UriSchemeHttps
                };
                //Redirect
                entity.Redirect(RedirectType.Moved, ub.Uri);
                return FileProcessArgs.VirtualSkip;
            }
            //Check for cors mode
            if (AllowCors && entity.Server.IsCors())
            {
                //set the allow credentials header
                entity.Server.Headers["Access-Control-Allow-Credentials"] = "true";
                //If cross site flag is set, or the connection has cross origin flag set, set explicit origin
                if (entity.Server.CrossOrigin || entity.Server.IsCrossSite() && entity.Server.Origin != null)
                {
                    entity.Server.Headers["Access-Control-Allow-Origin"] = $"{entity.Server.RequestUri.Scheme}://{entity.Server.Origin!.Authority}";
                    //Add origin to the response vary header when setting cors origin
                    entity.Server.Headers[HttpResponseHeader.Vary] = "Origin";
                }
            }
            //Always set refer policy
            if (RefererPolicy != null)
            {
                entity.Server.Headers["Referrer-Policy"] = RefererPolicy;
            }
            /*
             * Upstream server will handle the transport security,
             * if the connection is not from an upstream server 
             * and is using transport security then we can specify HSTS
             */
            if (entity.IsSecure && HSTSHeader != null)
            {
                entity.Server.Headers["Strict-Transport-Security"] = HSTSHeader;
            }
            return FileProcessArgs.Continue;
        }

        protected override ValueTask<FileProcessArgs> RouteFileAsync(HttpEntity entity)
        {
            //Only process the file if the connection is a browser
            if (!entity.Server.IsBrowser() || entity.Server.Method != HttpMethod.GET)
            {
                return new ValueTask<FileProcessArgs>(FileProcessArgs.Deny);
            }
            return base.RouteFileAsync(entity);
        }

        public override void PostProcessFile(in HttpEntity entity, in FileProcessArgs chosenRoutine)
        {
            //Set some protection headers
            entity.Server.Headers["X-Content-Type-Options"] = "nonsniff";
            //Get the re-written url or 
            ReadOnlySpan<char> ext;
            switch (chosenRoutine.Routine)
            {
                case FpRoutine.Deny:
                case FpRoutine.Error:
                case FpRoutine.NotFound:
                case FpRoutine.Redirect:
                    {
                        ReadOnlySpan<char> filePath = entity.Server.Path.AsSpan();
                        //disable cache
                        entity.Server.SetCache(CacheType.NoCache | CacheType.NoStore, TimeSpan.Zero);
                        //If the file is an html file or does not include an extension (inferred html) 
                        ext = Path.GetExtension(filePath);
                    }
                    break;
                case FpRoutine.ServeOther:
                case FpRoutine.ServeOtherFQ:
                    {
                        ReadOnlySpan<char> filePath = chosenRoutine.Alternate.AsSpan();
                        //Use the alternal file path for extension
                        ext = Path.GetExtension(filePath);
                        //Set default cache
                        ContentType ct = HttpHelpers.GetContentTypeFromFile(filePath);
                        SetCache(in entity, ct);
                    }
                    break;
                default:
                    {
                        ReadOnlySpan<char> filePath = entity.Server.Path.AsSpan();
                        //If the file is an html file or does not include an extension (inferred html) 
                        ext = Path.GetExtension(filePath);
                        if (ext.IsEmpty)
                        {
                            //If no extension, use .html extension
                            SetCache(in entity, ContentType.Html);
                        }
                        else
                        {
                            //Set default cache
                            ContentType ct = HttpHelpers.GetContentTypeFromFile(filePath);
                            SetCache(in entity, ct);
                        }
                    }
                    break;
            }
            if (ext.IsEmpty || ext.Equals(".html", StringComparison.OrdinalIgnoreCase))
            {
                entity.Server.Headers["X-XSS-Protection"] = "1; mode=block;";
                //Setup content-security policy
                entity.Server.Headers["Content-Security-Policy"] = ContentSecurityPolicy;
            }
        }

        private static readonly string NoCacheCacheControl = HttpHelpers.GetCacheString(CacheType.NoCache | CacheType.NoStore | CacheType.Revalidate);

        private readonly Lazy<string> DefaultCacheString;

        private void SetCache(in HttpEntity entity, ContentType ct)
        {
            //If request issued no cache request, set nocache headers
            if (entity.Server.NoCache())
            {
                entity.Server.Headers[HttpResponseHeader.Pragma] = "no-cache";
                entity.Server.Headers[HttpResponseHeader.CacheControl] = NoCacheCacheControl;
            }
            else
            {
                switch (ct)
                {
                    case ContentType.Css:
                    case ContentType.Jpeg:
                    case ContentType.Javascript:
                    case ContentType.Svg:
                    case ContentType.Img:
                    case ContentType.Png:
                    case ContentType.Apng:
                    case ContentType.Avi:
                    case ContentType.Avif:
                    case ContentType.Gif:
                        entity.Server.Headers[HttpResponseHeader.CacheControl] = DefaultCacheString.Value;
                        break;
                    case ContentType.NonSupported:
                        break;
                    default:
                        entity.Server.Headers[HttpResponseHeader.Pragma] = "no-cache";
                        entity.Server.Headers[HttpResponseHeader.CacheControl] = NoCacheCacheControl;
                        break;
                }
            }
        }
    }
}