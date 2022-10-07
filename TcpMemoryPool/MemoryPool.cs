using System;
using System.Buffers;

using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;

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
        public static MemoryPool<T> GetPool<T>() where T: unmanaged
        {           
            if (Memory.IsRpMallocLoaded)
            {
                //The rpmalloc lib is loaded, it is safe to convert the shared heap to a pool
                return RpMallocPrivateHeap.GlobalHeap.ToPool<T>();
            }
            //Use process heap
            else
            {
                return new ProcessHeap().ToPool<T>();
            }
        }
    }
}
