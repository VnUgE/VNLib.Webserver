using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Net.Security;
using System.Threading.Tasks;
using System.Security.Authentication;
using System.Runtime.CompilerServices;

using VNLib.Net.Http;
using VNLib.Net.Transport.Tcp;
#nullable enable

namespace VNLib.WebServer.Transport
{
    /// <summary>
    /// A TCP server transport provider class
    /// </summary>
    internal class TcpTransportProvider : ITransportProvider
    {
        private readonly TcpServer _server;

        public TcpTransportProvider(TCPConfig config)
        {
            _server = new(config);
        }

        ///<inheritdoc/>
        async ValueTask<ITransportContext> ITransportProvider.AcceptAsync(CancellationToken cancellation)
        {
            //Wait for tcp event and wrap in ctx class
            TransportEventContext ctx = await _server.AcceptAsync(cancellation);
            //Wrap event
            return new TcpTransportContext(_server, in ctx);
        }
        ///<inheritdoc/>
        void ITransportProvider.Start(CancellationToken stopToken)
        {
            //Start the server
            _server.Start(stopToken);
        }

        /// <summary>
        /// The TCP connection context
        /// </summary>
        class TcpTransportContext : ITransportContext
        {
            private readonly TransportEventContext _eventContext;
            private readonly TcpServer _server;

            private readonly Lazy<TransportSecurityInfo>? _securityInfo;

            public TcpTransportContext(TcpServer server, in TransportEventContext ctx)
            {
                _eventContext = ctx;
                _server = server;

                //Only set the sec info lazy if the connection is secure
                if (ctx.SslVersion > SslProtocols.None)
                {
                    //Thread saftey is not requird since the http server and api is thread safe
                    _securityInfo = new (getSecInfo, false);
                }
            }
            
            //Lazy load sec info
            TransportSecurityInfo getSecInfo()
            {
                //If this method is called then the connection is using tls
                SslStream ssl = (_eventContext.ConnectionStream as SslStream)!;

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
            Stream ITransportContext.ConnectionStream
            {
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
                get => _eventContext.ConnectionStream;
            }
            ///<inheritdoc/>
            SslProtocols ITransportContext.SslVersion
            {
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
                get => _eventContext.SslVersion;
            }
            ///<inheritdoc/>
            IPEndPoint ITransportContext.LocalEndPoint
            {
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
                get => _eventContext.LocalEndPoint;
            }
            ///<inheritdoc/>
            IPEndPoint ITransportContext.RemoteEndpoint
            {
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
                get => _eventContext.RemoteEndpoint;
            }

            ///<inheritdoc/>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            async ValueTask ITransportContext.CloseConnectionAsync()
            {
                //Close the connection with the TCP server
                await _server.CloseConnectionAsync(_eventContext);
            }

            
            TransportSecurityInfo? ITransportContext.GetSecurityInfo() => _securityInfo?.Value;
        }
    }
}
