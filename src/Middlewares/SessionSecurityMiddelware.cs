/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: SessionSecurityMiddelware.cs 
*
* SessionSecurityMiddelware.cs is part of VNLib.WebServer which is part of the larger 
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
using System.Threading.Tasks;
using System.Security.Authentication;

using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials;
using VNLib.Plugins.Essentials.Sessions;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Essentials.Middleware;

namespace VNLib.WebServer.Middlewares
{
    /// <summary>
    /// Adds required http session protections to http servers
    /// </summary>
    /// <param name="Log"></param>
    [MiddlewareImpl(MiddlewareImplOptions.SecurityCritical)]
    internal sealed record class SessionSecurityMiddelware(ILogProvider Log) : IHttpMiddleware
    {
        public ValueTask<FileProcessArgs> ProcessAsync(HttpEntity entity)
        {
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
                     * If the session was created from a different origin or the current connection
                     * is cross origin, then the origin must match the stored origin.
                     */

                    if ((entity.Server.CrossOrigin || entity.Session.CrossOrigin)
                        && !entity.Session.CrossOriginMatch
                        && entity.Server.Origin != null)
                    {
                        Log.Debug("Denied connection from {0} due to cross-origin session mismatch.", entity.TrustedRemoteIp);
                        return ValueTask.FromResult(FileProcessArgs.Deny);
                    }

                    //Try to prevent security downgrade attacks
                    if (!(entity.Session.IPMatch && entity.Session.SecurityProcol <= entity.Server.GetSslProtocol()))
                    {
                        Log.Debug("Denied connection from {0} due to security downgrade attack.", entity.TrustedRemoteIp);
                        return ValueTask.FromResult(FileProcessArgs.Deny);
                    }
                }
            }

            return ValueTask.FromResult(FileProcessArgs.Continue);
        }
    }
}