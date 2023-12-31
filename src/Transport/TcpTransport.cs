﻿/*
* Copyright (c) 2024 Vaughn Nugent
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
        /// <returns>The ssl configured transport context</returns>
        public static ITransportProvider CreateServer(in TCPConfig config, SslServerAuthenticationOptions ssl)
        {
            /*
             * SSL STREAM WORKAROUND
             * 
             * The HttpServer impl calls Read() synchronously on the calling thread, 
             * it assumes that the call will make it synchronously to the underlying 
             * transport. SslStream calls ReadAsync() interally on the current 
             * synchronization context, which causes a deadlock... So the threadpool 
             * scheduler on the pipeline ensures that all continuations are run on the
             * threadpool, which fixes this issue.
             */

            //Create tcp server 
            TcpServer server = new (config, CreateCustomPipeOptions(in config, false));
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
                _ = Server.Start(stopToken);
            }

            ///<inheritdoc/>
            public virtual async ValueTask<ITransportContext> AcceptAsync(CancellationToken cancellation)
            {
                //Wait for tcp event and wrap in ctx class
                ITcpConnectionDescriptor descriptor = await Server.AcceptConnectionAsync(cancellation);
                //Wrap event
                return new TcpTransportContext(Server, descriptor, descriptor.GetStream());
            }
        }

        private sealed record class SslTcpTransportProvider(TcpServer Server, SslServerAuthenticationOptions AuthOptions) : TcpTransportProvider(Server)
        {
            public override async ValueTask<ITransportContext> AcceptAsync(CancellationToken cancellation)
            {
                //Wait for tcp event and wrap in ctx class
                ITcpConnectionDescriptor descriptor = await Server.AcceptConnectionAsync(cancellation);

                //Create ssl stream and auth
                SslStream stream = new(descriptor.GetStream(), false);

                try
                {
                    //auth the new connection
                    await stream.AuthenticateAsServerAsync(AuthOptions, cancellation);
                    return new SslTcpTransportContext(Server, descriptor, stream);                    
                }
                catch
                {
                    await Server.CloseConnectionAsync(descriptor);
                    await stream.DisposeAsync();
                    throw;
                }
            }
        }
    }
}
