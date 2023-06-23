/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: TcpTransport.cs 
*
* TcpTransport.cs is part of VNLib.WebServer which is part of the larger 
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

using System.Threading;
using System.IO.Pipelines;
using System.Net.Security;
using System.Threading.Tasks;

using VNLib.Net.Http;
using VNLib.Net.Transport.Tcp;


namespace VNLib.WebServer.Transport
{
    /// <summary>
    /// Creates the TCP/HTTP translation layer providers
    /// </summary>
    internal static class TcpTransport
    {
        /// <summary>
        /// Creates a new <see cref="ITransportProvider"/> that will listen for tcp connections
        /// </summary>
        /// <param name="config">The server configuration</param>
        /// <param name="inlineScheduler">Use the inline pipeline scheduler</param>
        /// <returns>The configured <see cref="ITransportProvider"/></returns>
        public static ITransportProvider CreateServer(in TCPConfig config, bool inlineScheduler)
        {
            //Create tcp server
            TcpServer server = new (config, CreateCustomPipeOptions(in config, inlineScheduler));
            //Return provider
            return new TcpTransportProvider(server);
        }

        /// <summary>
        /// Creates a new <see cref="ITransportProvider"/> that will listen for tcp connections
        /// and use SSL
        /// </summary>
        /// <param name="config"></param>
        /// <param name="ssl">The server authentication options</param>
        /// <param name="inlineScheduler">Use the inline pipeline scheduler</param>
        /// <returns>The ssl configured transport context</returns>
        public static ITransportProvider CreateServer(in TCPConfig config, SslServerAuthenticationOptions ssl, bool inlineScheduler)
        {
            //Create tcp server
            TcpServer server = new (config, CreateCustomPipeOptions(in config, inlineScheduler));
            //Return provider
            return new SslTcpTransportProvider(server, ssl);
        }

        private static PipeOptions CreateCustomPipeOptions(in TCPConfig config, bool inlineScheduler)
        {
            return new PipeOptions(
                config.BufferPool,
                //Noticable performance increase when using inline scheduler for reader (hanles send operations)
                readerScheduler: inlineScheduler ? PipeScheduler.Inline : PipeScheduler.ThreadPool,
                writerScheduler: inlineScheduler ? PipeScheduler.Inline : PipeScheduler.ThreadPool,
                pauseWriterThreshold: config.MaxRecvBufferData,
                minimumSegmentSize: 8192,
                useSynchronizationContext: false
                );
        }

        /// <summary>
        /// A TCP server transport provider class
        /// </summary>
        private record class TcpTransportProvider(TcpServer Server) : ITransportProvider
        {
            ///<inheritdoc/>
            void ITransportProvider.Start(CancellationToken stopToken)
            {
                //Start the server
                Server.Start(stopToken);
            }

            ///<inheritdoc/>
            public virtual async ValueTask<ITransportContext> AcceptAsync(CancellationToken cancellation)
            {
                //Wait for tcp event and wrap in ctx class
                TransportEventContext ctx = await Server.AcceptAsync(cancellation);
                //Wrap event
                return new TcpTransportContext(in ctx);
            }
        }

        private record class SslTcpTransportProvider(TcpServer Server, SslServerAuthenticationOptions AuthOptions) : TcpTransportProvider(Server)
        {
            public override async ValueTask<ITransportContext> AcceptAsync(CancellationToken cancellation)
            {
                //Wait for tcp event and wrap in ctx class
                TransportEventContext ctx = await Server.AcceptSslAsync(AuthOptions, cancellation);
                //Wrap event
                return new SslTcpTransportContext(in ctx);
            }
        }
    }
}
