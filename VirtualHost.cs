/*
* Copyright (c) 2022 Vaughn Nugent
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
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using System.Security.Authentication;

using VNLib.Net.Http;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials;
using VNLib.Plugins.Essentials.Sessions;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Essentials.ServiceStack;

namespace VNLib.WebServer
{

    internal sealed class VirtualHost : EventProcessor, IServiceHost
    {
        private const int FILE_PATH_BUILDER_BUFFER_SIZE = 4096;

        private readonly DirectoryInfo Root;
        
        public ReadOnlyDictionary<HttpStatusCode, FailureFile> FailureFiles { get; init; }
      
        ///<inheritdoc/>
        public override string Hostname { get; }
        ///<inheritdoc/>
        public override string Directory => Root.FullName;
        ///<inheritdoc/>
        protected override ILogProvider Log { get; }

        ///<inheritdoc/>
        public override IEpProcessingOptions Options => VirtualHostOptions;

        public EPOptionsImpl VirtualHostOptions { get; init; }

        //Explict pass of service host information
        EventProcessor IServiceHost.Processor => this;
        IHostTransportInfo IServiceHost.TransportInfo => VirtualHostOptions;

#nullable disable
        public VirtualHost(string path, string hostName, ILogProvider log)
        {
            Root = new DirectoryInfo(path);
            if (!Root.Exists)
            {
                Root.Create();
            }
            Hostname = hostName;
            //Inint default cache string
            DefaultCacheString = new(() => 
                HttpHelpers.GetCacheString(CacheType.Public, (int)VirtualHostOptions.CacheDefault.TotalSeconds),
                System.Threading.LazyThreadSafetyMode.PublicationOnly
            );
            Log = log;
        }
#nullable enable

        public override bool ErrorHandler(HttpStatusCode errorCode, IHttpEvent ev)
        {
            //Make sure the connection accepts html
            if (ev.Server.Accepts(ContentType.Html) && FailureFiles.TryGetValue(errorCode, out FailureFile? ff))
            {
                ev.Server.SetNoCache();
                ev.CloseResponse(errorCode, ContentType.Html, ff.File);
                return true;
            }
            return false;
        }

        public override string TranslateResourcePath(string requestPath)
        {
            //Filter the path using the supplied regex
            requestPath = VirtualHostOptions.PathFilter?.Replace(requestPath, string.Empty) ?? requestPath;
            //Alloc temp buffer from the shared heap, 
            using UnsafeMemoryHandle<char> charBuffer = Memory.UnsafeAlloc<char>(FILE_PATH_BUILDER_BUFFER_SIZE);
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
                return ValueTask.FromResult(FileProcessArgs.Deny);
            }
          

            /*
             * downstream server will handle the transport security,
             * if the connection is not from an downstream server 
             * and is using transport security then we can specify HSTS
             */
            if (entity.IsSecure && VirtualHostOptions.HSTSHeader != null)
            {
                entity.Server.Headers["Strict-Transport-Security"] = VirtualHostOptions.HSTSHeader;
            }
            //Always set refer policy
            if (VirtualHostOptions.RefererPolicy != null)
            {
                entity.Server.Headers["Referrer-Policy"] = VirtualHostOptions.RefererPolicy;
            }

            //Check coors enabled
            bool isCors = entity.Server.IsCors();

            /*
             * Deny/allow cross site/cors requests at the site-level
             */
            if (VirtualHostOptions.AllowCors)
            {
                if (isCors)
                {
                    //set the allow credentials header
                    entity.Server.Headers["Access-Control-Allow-Credentials"] = "true";
                    //If cross site flag is set, or the connection has cross origin flag set, set explicit origin
                    if (entity.Server.CrossOrigin || entity.Server.IsCrossSite() && entity.Server.Origin != null)
                    {
                        entity.Server.Headers["Access-Control-Allow-Origin"] = $"{entity.Server.RequestUri.Scheme}://{entity.Server.Origin!.Authority}";
                        //Add origin to the response vary header when setting cors origin
                        entity.Server.Headers.Append(HttpResponseHeader.Vary, "Origin");
                    }
                }

                //Add sec vary headers for cors enabled sites
                entity.Server.Headers.Append(HttpResponseHeader.Vary, "Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site");
            }
            else
            {
                if(isCors || entity.Server.IsCrossSite())
                {
                    return ValueTask.FromResult(FileProcessArgs.Deny);
                }
            }

            //If user-navigation is set and method is get, make sure it does not contain object/embed
            if (entity.Server.IsNavigation() && entity.Server.Method == HttpMethod.GET)
            {
                string? dest = entity.Server.Headers["sec-fetch-dest"];
                if(dest != null && (dest.Contains("object", StringComparison.OrdinalIgnoreCase) || dest.Contains("embed")))
                {
                    return ValueTask.FromResult(FileProcessArgs.Deny);
                }
            }

            //If the connection is cors, then an origin header must be supplied
            if (isCors)
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
                    if (!(entity.Session.IPMatch 
                        && entity.Session.UserAgent.Equals(entity.Server.UserAgent, StringComparison.Ordinal)
                        && entity.Session.SecurityProcol <= entity.Server.SecurityProtocol)
                    )
                    {
                        return ValueTask.FromResult(FileProcessArgs.Deny);
                    }
                }

                //Reconcile cookies with the session
                entity.ReconcileCookies();
               
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
            if (ext.IsEmpty || ext.Equals(".html", StringComparison.OrdinalIgnoreCase))
            {
                entity.Server.Headers.Append("X-XSS-Protection", "1; mode=block;");
                //Setup content-security policy
                entity.Server.Headers.Append("Content-Security-Policy", VirtualHostOptions.ContentSecurityPolicy);
            }
        }

        private readonly Lazy<string> DefaultCacheString;

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
                        entity.Server.Headers[HttpResponseHeader.CacheControl] = DefaultCacheString.Value;
                        return;
                    case ContentType.NonSupported:
                        return;
                    default:
                        entity.Server.SetNoCache();
                        break;
                }
            }
            entity.Server.SetNoCache();
        }
    }
}