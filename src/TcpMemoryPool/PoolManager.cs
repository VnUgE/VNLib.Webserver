/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: PoolManager.cs 
*
* MemoryPool.cs is part of VNLib.WebServer which is part of the larger 
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
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Net.Http;


namespace VNLib.WebServer.TcpMemoryPool
{
    /// <summary>
    /// recovers a memory pool for the TCP server to alloc buffers from
    /// </summary>
    internal static class PoolManager
    {
        /// <summary>
        /// Gets an unmanaged memory pool provider for the TCP server to alloc buffers from
        /// </summary>
        /// <typeparam name="T">The pool type to create</typeparam>
        /// <returns>The memory pool</returns>
        public static MemoryPool<byte> GetPool(bool zeroOnAlloc)
        {           
            //Use the shared heap impl. which also allows diagnostics, and is tuned
            return new HttpMemoryPool(zeroOnAlloc);
        }

        /// <summary>
        /// Gets a memory pool provider for the HTTP server to alloc buffers from
        /// </summary>
        /// <returns>The http server memory pool</returns>
        public static IHttpMemoryPool GetHttpPool(bool zeroOnAlloc) => new HttpMemoryPool(zeroOnAlloc);

        internal sealed class HttpMemoryPool : MemoryPool<byte>, IHttpMemoryPool
        {
            private readonly bool _zeroOnAlloc;

            public HttpMemoryPool(bool zeroOnAlloc)
            {
                _zeroOnAlloc = zeroOnAlloc;
            }

            ///<inheritdoc/>
            public override int MaxBufferSize { get; } = int.MaxValue;

            ///<inheritdoc/>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public IMemoryOwner<byte> AllocateBufferForContext(int bufferSize) => Rent(bufferSize);

            ///<inheritdoc/>
            public MemoryHandle<T> AllocFormDataBuffer<T>(int initialSize) where T : unmanaged
            {
                return MemoryUtil.Shared.Alloc<T>(initialSize, _zeroOnAlloc);
            }

            ///<inheritdoc/>
            public override IMemoryOwner<byte> Rent(int minBufferSize = -1)
            {
                nint toPage = MemoryUtil.NearestPage(minBufferSize);
                return new UnsafeMemoryManager(MemoryUtil.Shared, (nuint)toPage, _zeroOnAlloc);
            }

            ///<inheritdoc/>
            protected override void Dispose(bool disposing)
            { }

            sealed class UnsafeMemoryManager : MemoryManager<byte>
            {
                private readonly IUnmangedHeap _heap;

                private IntPtr _pointer;
                private int _size;

                public UnsafeMemoryManager(IUnmangedHeap heap, nuint bufferSize, bool zero)
                {
                    _size = (int)bufferSize;
                    _heap = heap;
                    _pointer = heap.Alloc(bufferSize, sizeof(byte), zero);
                }

                public override Span<byte> GetSpan()
                {
                    //Guard
                    Debug.Assert(_pointer != IntPtr.Zero, "Pointer to memory block is null, was not allocated properly or was released");

                    return MemoryUtil.GetSpan<byte>(_pointer, _size);
                }

                public override MemoryHandle Pin(int elementIndex = 0)
                {
                    //Guard
                    if(elementIndex >= _size || elementIndex < 0)
                    {
                        throw new ArgumentOutOfRangeException(nameof(elementIndex));
                    }

                    Debug.Assert(_pointer != IntPtr.Zero, "Pointer to memory block is null, was not allocated properly or was released");

                    //Get pointer offset from index
                    IntPtr offset = IntPtr.Add(_pointer, elementIndex);

                    //Return handle at offser
                    return MemoryUtil.GetMemoryHandleFromPointer(offset, pinnable:this);
                }

                public override void Unpin()
                {
                    //No-op
                }

                protected override void Dispose(bool disposing)
                {
                    Debug.Assert(_pointer != IntPtr.Zero, "Pointer to memory block is null, was not allocated properly");

                    //Free the memory, should also zero the pointer
                    _heap.Free(ref _pointer);
                    
                    //Set size to 0
                    _size = 0;
                }
            }
        }
    }

    
}
