using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Authentication;
using System.Runtime.CompilerServices;

using VNLib.Net.Http;
using VNLib.Net.Transport.Tcp;

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

            public TcpTransportContext(TcpServer server, in TransportEventContext ctx)
            {
                _eventContext = ctx;
                _server = server;
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
        }
    }
}
