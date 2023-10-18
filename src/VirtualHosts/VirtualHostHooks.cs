﻿/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: VirtualHostHooks.cs 
*
* VirtualHostHooks.cs is part of VNLib.WebServer which is part of the larger 
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
using System.Globalization;
using System.Runtime.CompilerServices;

using VNLib.Net.Http;
using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Essentials.ServiceStack.Construction;

namespace VNLib.WebServer
{

    internal sealed class VirtualHostHooks: IVirtualHostHooks
    {
        private const int FILE_PATH_BUILDER_BUFFER_SIZE = 4096;

        private static readonly string CultreInfo = CultureInfo.InstalledUICulture.Name;
     
        private readonly string DefaultCacheString;

        public VirtualHostConfig VirtualHostOptions { get; }


        public VirtualHostHooks(VirtualHostConfig config)
        {
            VirtualHostOptions = config;

            //Inint default cache string
            DefaultCacheString = HttpHelpers.GetCacheString(CacheType.Public, (int)config.CacheDefault.TotalSeconds);
        }

        public bool ErrorHandler(HttpStatusCode errorCode, IHttpEvent ev)
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
        public string TranslateResourcePath(string requestPath)
        {
            //Filter the path using the supplied regex
            requestPath = VirtualHostOptions.PathFilter?.Replace(requestPath, string.Empty) ?? requestPath;
            //Alloc temp buffer from the shared heap, 
            using UnsafeMemoryHandle<char> charBuffer = MemoryUtil.UnsafeAlloc<char>(FILE_PATH_BUILDER_BUFFER_SIZE);
            //Buffer writer
            ForwardOnlyWriter<char> sb = new(charBuffer.Span);
            //Start with the root filename
            sb.Append(VirtualHostOptions.RootDir.FullName);
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

        public void PreProcessEntityAsync(HttpEntity entity, out FileProcessArgs args)
        {
            args = FileProcessArgs.Continue;
        }

        public void PostProcessFile(HttpEntity entity, ref FileProcessArgs chosenRoutine)
        {
            //Do not respond to virtual processors
            if (chosenRoutine == FileProcessArgs.VirtualSkip)
            {
                return;
            }

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

                        //Use the alternate file path for extension
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