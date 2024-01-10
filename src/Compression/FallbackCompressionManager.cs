﻿/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: FallbackCompressionManager.cs 
*
* FallbackCompressionManager.cs is part of VNLib.WebServer which is part 
* of the larger VNLib collection of libraries and utilities.
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
using System.Buffers;
using System.Diagnostics;
using System.IO.Compression;

using VNLib.Net.Http;
using VNLib.Utils.Memory;

namespace VNLib.WebServer.Compression
{

    /*
     * The fallback compression manager is used when the user did not configure a 
     * compression manager library. Since .NET only exposes a brotli encoder, that 
     * is not a stream api, (gzip and deflate are stream api's) Im only supporting
     * brotli for now. This is better than nothing lol 
     */


    internal sealed class FallbackCompressionManager : IHttpCompressorManager
    {
        /// <inheritdoc/>
        public object AllocCompressor() => new BrCompressorState();

        /// <inheritdoc/>
        public CompressionMethod GetSupportedMethods() => CompressionMethod.Brotli;

        /// <inheritdoc/>
        public int InitCompressor(object compressorState, CompressionMethod compMethod)
        {
            BrCompressorState compressor = (BrCompressorState)compressorState;
            ref BrotliEncoder encoder = ref compressor.GetEncoder();

            //Init new brotli encoder struct
            encoder = new(9, 24);
            compressor.LastBlockWritten = false;    //Clear flag before reusing
            return 0;
        }

        /// <inheritdoc/>
        public void DeinitCompressor(object compressorState)
        {
            BrCompressorState compressor = (BrCompressorState)compressorState;
            ref BrotliEncoder encoder = ref compressor.GetEncoder();

            //Clean up the encoder
            encoder.Dispose();
            encoder = default;
        }

        /// <inheritdoc/>
        public CompressionResult CompressBlock(object compressorState, ReadOnlyMemory<byte> input, Memory<byte> output)
        {           
            //Output buffer should never be empty, server guards this
            Debug.Assert(!output.IsEmpty, "Exepcted a non-zero length output buffer");

            BrCompressorState compressor = (BrCompressorState)compressorState;
            ref BrotliEncoder encoder = ref compressor.GetEncoder();

            //Compress the supplied block
            OperationStatus status = encoder.Compress(input.Span, output.Span, out int bytesConsumed, out int bytesWritten, false);
            
            /*
             * Should always return done, because the output buffer is always 
             * large enough and that data/state cannot be invalid
             */
            Debug.Assert(status == OperationStatus.Done);

            return new()
            {
                BytesRead = bytesConsumed,
                BytesWritten = bytesWritten,
            };
        }

        /// <inheritdoc/>
        public int Flush(object compressorState, Memory<byte> output)
        {
            OperationStatus status;
            int bytesWritten;

            //Output buffer should never be empty, server guards this
            Debug.Assert(!output.IsEmpty, "Exepcted a non-zero length output buffer");

            BrCompressorState compressor = (BrCompressorState)compressorState;
            ref BrotliEncoder encoder = ref compressor.GetEncoder();

            ForwardOnlyWriter<byte> writer = new(output.Span);

            if (!compressor.LastBlockWritten)
            {
                //Compress nothing with the the final block flag set
                status = encoder.Compress(default, writer.Remaining, out _, out bytesWritten, true);

                /*
                 * Should always return done, because the output buffer is always 
                 * large enough and that data/state cannot be invalid
                 */
                Debug.Assert(status == OperationStatus.Done);
                writer.Advance(bytesWritten);

                //Mark the last block as written
                compressor.LastBlockWritten = true;

                //May not have any space left after the last block
                if(writer.Remaining.IsEmpty)
                {
                    return writer.Written;
                }
            }

            //Flush remaining data
            status = encoder.Flush(output.Span, out bytesWritten);
            Debug.Assert(status == OperationStatus.Done);

            writer.Advance(bytesWritten);

            //Return the number of bytes actually accumulated
            return writer.Written;
        }
       

        private sealed class BrCompressorState
        {
            private BrotliEncoder _encoder;

            public ref BrotliEncoder GetEncoder() => ref _encoder;

            /// <summary>
            /// Tracks if the last block has been written during 
            /// a flush phase
            /// </summary>
            public bool LastBlockWritten;
        }
    }
}
