/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: TcpTransportContext.cs 
*
* TcpTransportContext.cs is part of VNLib.WebServer which is part of the larger 
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

using System.IO;
using System.Net;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;

using VNLib.Net.Http;
using VNLib.Net.Transport.Tcp;

namespace VNLib.WebServer.Transport
{
    /// <summary>
    /// The TCP connection context
    /// </summary>
    internal record class TcpTransportContext(in TransportEventContext EventContext) : ITransportContext
    {
        //Store static empty security info to pass in default case
        private static readonly TransportSecurityInfo? EmptySecInfo;

        ///<inheritdoc/>
        public virtual Stream ConnectionStream
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => EventContext.ConnectionStream;
        }

        ///<inheritdoc/>
        public virtual IPEndPoint LocalEndPoint
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => EventContext.LocalEndPoint;
        }

        ///<inheritdoc/>
        public virtual IPEndPoint RemoteEndpoint
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => EventContext.RemoteEndpoint;
        }

        ///<inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public virtual ValueTask CloseConnectionAsync()
        {
            //Close the connection with the TCP server
            return EventContext.CloseConnectionAsync();
        }

        //Ssl is not supported in this transport
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public virtual ref readonly TransportSecurityInfo? GetSecurityInfo() => ref EmptySecInfo;
    }
}
