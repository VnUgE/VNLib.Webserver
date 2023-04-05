/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: VirtualHost.cs 
*
* VirtualHost.cs is part of VNLib.WebServer which is part of the larger 
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
using System.Threading;
using System.Globalization;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Runtime.CompilerServices;

using VNLib.Net.Http;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials;
using VNLib.Plugins.Essentials.Sessions;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Extensions;

namespace VNLib.WebServer
{
    internal sealed class VirtualHost : EventProcessor
    {
        private const int FILE_PATH_BUILDER_BUFFER_SIZE = 4096;

        private static readonly string CultreInfo = CultureInfo.InstalledUICulture.Name;

        private readonly DirectoryInfo Root;
        private readonly string DefaultCacheString;

        ///<inheritdoc/>
        public override string Hostname { get; }

        ///<inheritdoc/>
        public override string Directory => VirtualHostOptions.FileRoot;

        ///<inheritdoc/>
        protected override ILogProvider Log { get; }

        ///<inheritdoc/>
        public override IReadOnlyDictionary<string, Redirect> Redirects => Options.HardRedirects;

        ///<inheritdoc/>
        public override IEpProcessingOptions Options => VirtualHostOptions;

        public VirtualHostConfig VirtualHostOptions { get; }

        private IAccountSecurityProvider _accountSecurityProvider;
        
        ///<inheritdoc/>
        public override IAccountSecurityProvider AccountSecurity => _accountSecurityProvider;


        public VirtualHost(string hostName, ILogProvider log, VirtualHostConfig config)
        {
            Root = new DirectoryInfo(config.FileRoot);

            Hostname = hostName;
            Log = log;
            VirtualHostOptions = config;

            //Inint default cache string
            DefaultCacheString = HttpHelpers.GetCacheString(CacheType.Public, (int)config.CacheDefault.TotalSeconds);

            //Configure a default provider
            _accountSecurityProvider = default!;
        }

        internal void SetSecurityProvider(IAccountSecurityProvider? secProv)
        {
            //Set to default provider
            secProv ??= default!;

            _ = Interlocked.Exchange(ref _accountSecurityProvider, secProv);
        }

        public override bool ErrorHandler(HttpStatusCode errorCode, IHttpEvent ev)
        {
            //Make sure the connection accepts html
            if (ev.Server.Accepts(ContentType.Html) && VirtualHostOptions.FailureFiles.TryGetValue(errorCode, out FailureFile? ff))
            {
                ev.Server.SetNoCache();
                ev.CloseResponse(errorCode, ContentType.Html, ff.GetReader());
                return true;
            }
            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public override string TranslateResourcePath(string requestPath)
        {
            //Filter the path using the supplied regex
            requestPath = VirtualHostOptions.PathFilter?.Replace(requestPath, string.Empty) ?? requestPath;
            //Alloc temp buffer from the shared heap, 
            using UnsafeMemoryHandle<char> charBuffer = MemoryUtil.UnsafeAlloc<char>(FILE_PATH_BUILDER_BUFFER_SIZE);
            //Buffer writer
            ForwardOnlyWriter<char> sb = new(charBuffer.Span);
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

        public override ValueTask<FileProcessArgs> PreProcessEntityAsync(HttpEntity entity)
        {
            entity.Server.Headers[HttpResponseHeader.Server] = "VNLib.Http/1.1";
            
            //Block websocket requests
            if (entity.Server.IsWebSocketRequest)
            {
                Log.Verbose("Client {ip} made a websocket request", entity.TrustedRemoteIp);
            }
            
            //If a whitelist has been defined, block requests from non-whitelisted IPs
            if (VirtualHostOptions.WhiteList != null && !VirtualHostOptions.WhiteList.Contains(entity.TrustedRemoteIp))
            {
                Log.Verbose("Client {ip} is not whitelisted, blocked", entity.TrustedRemoteIp);
                return ValueTask.FromResult(FileProcessArgs.Deny);
            }
            
            //Check transport security if set
            if(entity.Server.TransportSecurity.HasValue)
            {
                
            }

            //If not behind upstream server, uri ports and server ports must match
            if (!entity.IsBehindDownStreamServer && !entity.Server.EnpointPortsMatch())
            {
                Log.Debug("Connection received on port {p} but the client host port did not match at {pp}",
                    entity.Server.LocalEndpoint.Port, 
                    entity.Server.RequestUri.Port);

                return ValueTask.FromResult(FileProcessArgs.Deny);
            }          

            /*
             * downstream server will handle the transport security,
             * if the connection is not from an downstream server 
             * and is using transport security then we can specify HSTS
             */
            if (entity.IsSecure)
            {
                VirtualHostOptions.TrySetSpecialHeader(entity.Server, SpecialHeaders.Hsts);
            }

            //Check coors enabled
            bool isCors = entity.Server.IsCors();
            bool isCrossSite = entity.Server.IsCrossSite();

            /*
             * Deny/allow cross site/cors requests at the site-level
             */
            if (VirtualHostOptions.AllowCors)
            {
                //Confirm the origin is allowed during cors connections
                if (entity.Server.CrossOrigin && VirtualHostOptions.AllowedCorsAuthority != null)
                {
                    //If the authority is not allowed, deny the connection
                    if (!VirtualHostOptions.AllowedCorsAuthority.Contains(entity.Server.Origin!.Authority))
                    {
                        Log.Debug("Blocked a connection from a cross origin site {s}, because it was not whitelisted", entity.Server.Origin);
                        return ValueTask.FromResult(FileProcessArgs.Deny);
                    }
                }

                if (isCors)
                {
                    //set the allow credentials header
                    entity.Server.Headers["Access-Control-Allow-Credentials"] = "true";

                    //If cross site flag is set, or the connection has cross origin flag set, set explicit origin
                    if (entity.Server.CrossOrigin || isCrossSite && entity.Server.Origin != null)
                    {
                        entity.Server.Headers["Access-Control-Allow-Origin"] = $"{entity.Server.RequestUri.Scheme}://{entity.Server.Origin!.Authority}";
                        //Add origin to the response vary header when setting cors origin
                        entity.Server.Headers.Append(HttpResponseHeader.Vary, "Origin");
                    }
                }

                //Add sec vary headers for cors enabled sites
                entity.Server.Headers.Append(HttpResponseHeader.Vary, "Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site");
            }
            else if (isCors | isCrossSite)
            {
                return ValueTask.FromResult(FileProcessArgs.Deny);
            }

            //If user-navigation is set and method is get, make sure it does not contain object/embed
            if (entity.Server.IsNavigation() && entity.Server.Method == HttpMethod.GET)
            {
                string? dest = entity.Server.Headers["sec-fetch-dest"];
                if(dest != null && (dest.Contains("object", StringComparison.OrdinalIgnoreCase) || dest.Contains("embed", StringComparison.OrdinalIgnoreCase)))
                {
                    return ValueTask.FromResult(FileProcessArgs.Deny);
                }
            }

            //If the connection is a cross-site, then an origin header must be supplied
            if (isCrossSite)
            {
                //Enforce origin header
                if (entity.Server.Origin == null)
                {
                    return ValueTask.FromResult(FileProcessArgs.Deny);
                }
            }

            //If same origin is supplied, enforce origin header on post/options/put/patch
            if ("same-origin".Equals(entity.Server.Headers["Sec-Fetch-Site"], StringComparison.OrdinalIgnoreCase))
            {
                //If method is not get/head, then origin is required
                if ((entity.Server.Method & (HttpMethod.GET | HttpMethod.HEAD)) == 0 && entity.Server.Origin == null)
                {
                    return ValueTask.FromResult(FileProcessArgs.Deny);
                }
            }

            if (entity.Session.IsSet)
            {

                /*
                * Check if the session was established over a secure connection, 
                * and if the current connection is insecure, redirect them to a 
                * secure connection.
                */
                if (entity.Session.SecurityProcol > SslProtocols.None && !entity.IsSecure)
                {
                    //Redirect the client to https
                    UriBuilder ub = new(entity.Server.RequestUri)
                    {
                        Scheme = Uri.UriSchemeHttps
                    };
                    //Redirect
                    entity.Redirect(RedirectType.Moved, ub.Uri);
                    return ValueTask.FromResult(FileProcessArgs.VirtualSkip);
                }

                //If session is not new, then verify it matches stored credentials
                if (!entity.Session.IsNew && entity.Session.SessionType == SessionType.Web)
                {
                    /*
                     * When sessions are created for connections that come from a different 
                     * origin, their origin is stored for later. 
                     * 
                     * Check that the origin's match the current origin, it may be false if 
                     * the current origin is null, so if the origin is set and the origins dont 
                     * match, deny the request
                     */
                    if(!entity.Session.CrossOriginMatch && entity.Server.Origin != null)
                    {
                        return ValueTask.FromResult(FileProcessArgs.Deny);
                    }

                    if (!(entity.Session.IPMatch && entity.Session.SecurityProcol <= entity.Server.SecurityProtocol))
                    {
                        return ValueTask.FromResult(FileProcessArgs.Deny);
                    }
                    //If the session stored a user-agent, make sure it matches the connection
                    else if (entity.Session.UserAgent != null && !entity.Session.UserAgent.Equals(entity.Server.UserAgent, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult(FileProcessArgs.Deny);
                    }
                }
            }            

            //Add response headers from vh config
            for(int i = 0; i < VirtualHostOptions.AdditionalHeaders.Count; i++)
            {
                //Get and append the client header value
                KeyValuePair<string, string> header = VirtualHostOptions.AdditionalHeaders[i];

                entity.Server.Headers.Append(header.Key, header.Value);
            }

            return ValueTask.FromResult(FileProcessArgs.Continue);
        }

        protected override ValueTask<FileProcessArgs> RouteFileAsync(HttpEntity entity)
        {
            //Only process the file if the connection is a browser
            if (!entity.Server.IsBrowser() || entity.Server.Method != HttpMethod.GET)
            {
                entity.CloseResponse(HttpStatusCode.Forbidden);
                return ValueTask.FromResult(FileProcessArgs.VirtualSkip);
            }
            return base.RouteFileAsync(entity);
        }

        public override void PostProcessFile(HttpEntity entity, in FileProcessArgs chosenRoutine)
        {
            //Get-set the x-content options headers from the client config
            VirtualHostOptions.TrySetSpecialHeader(entity.Server, SpecialHeaders.XContentOption);

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
                        entity.Server.SetNoCache();

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
                        SetCache(entity, ct);
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
                            SetCache(entity, ContentType.Html);
                        }
                        else
                        {
                            //Set default cache
                            ContentType ct = HttpHelpers.GetContentTypeFromFile(filePath);
                            SetCache(entity, ct);
                        }
                    }
                    break;
            }
            
            //if the file is an html file, we are setting the csp and xss special headers
            if (ext.IsEmpty || ext.Equals(".html", StringComparison.OrdinalIgnoreCase))
            {
                //Get/set xss protection header
                VirtualHostOptions.TrySetSpecialHeader(entity.Server, SpecialHeaders.XssProtection);
                VirtualHostOptions.TrySetSpecialHeader(entity.Server, SpecialHeaders.ContentSecPolicy);
            }

            //Set language of the server's os if the user code did not set it
            if (!entity.Server.Headers.HeaderSet(HttpResponseHeader.ContentLanguage))
            {
                entity.Server.Headers[HttpResponseHeader.ContentLanguage] = CultreInfo;
            }
        }

        private void SetCache(HttpEntity entity, ContentType ct)
        {
            //If request issued no cache request, set nocache headers
            if (!entity.Server.NoCache())
            {
                //Otherwise set caching based on the file extension type
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
                        entity.Server.Headers[HttpResponseHeader.CacheControl] = DefaultCacheString;
                        return;
                    case ContentType.NonSupported:
                        return;
                    default:
                        break;
                }
            }
            entity.Server.SetNoCache();
        }
    }
}