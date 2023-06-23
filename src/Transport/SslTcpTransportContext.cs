/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: SslTcpTransportContext.cs 
*
* SslTcpTransportContext.cs is part of VNLib.WebServer which is part of the larger 
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
using System.Net.Security;
using System.Threading.Tasks;
using System.Security.Authentication;
using System.Runtime.CompilerServices;

using VNLib.Net.Http;
using VNLib.Net.Transport.Tcp;

namespace VNLib.WebServer.Transport
{
    sealed record class SslTcpTransportContext : TcpTransportContext
    {
        private readonly Lazy<TransportSecurityInfo> _securityInfo;

        public SslTcpTransportContext(in TransportEventContext ctx) : base(ctx)
        {
            //Store the ssl version of the connection
            SslVersion = ctx.GetSslProtocol();

            //Thread saftey is not requird since the http server and api is thread safe
            _securityInfo = new(getSecInfo, false);
        }

        //Lazy load sec info
        TransportSecurityInfo getSecInfo()
        {
            //If this method is called then the connection is using tls
            SslStream ssl = (EventContext.ConnectionStream as SslStream)!;

            //Build sec info
            TransportSecurityInfo so = new()
            {
                HashAlgorithm = ssl.HashAlgorithm,
                CipherAlgorithm = ssl.CipherAlgorithm,

                HashStrength = ssl.HashStrength,
                CipherStrength = ssl.CipherStrength,

                IsSigned = ssl.IsSigned,
                IsEncrypted = ssl.IsEncrypted,
                IsAuthenticated = ssl.IsAuthenticated,
                IsMutuallyAuthenticated = ssl.IsMutuallyAuthenticated,
                CheckCertRevocationStatus = ssl.CheckCertRevocationStatus,

                KeyExchangeStrength = ssl.KeyExchangeStrength,
                KeyExchangeAlgorithm = ssl.KeyExchangeAlgorithm,

                LocalCertificate = ssl.LocalCertificate,
                RemoteCertificate = ssl.RemoteCertificate,

                TransportContext = ssl.TransportContext,
                NegotiatedCipherSuite = ssl.NegotiatedCipherSuite,
                NegotiatedApplicationProtocol = ssl.NegotiatedApplicationProtocol,
            };
            return so;
        }

        ///<inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public override ValueTask CloseConnectionAsync()
        {
            //Close the connection with the TCP server using the ssl overrides
            return EventContext.CloseSslConnectionAsync();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public override TransportSecurityInfo? GetSecurityInfo() => _securityInfo.Value;

        ///<inheritdoc/>
        public override SslProtocols SslVersion { get; }

    }
}
