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
            if (Memory.Shared is RpMallocPrivateHeap)
            {
                //The rpmalloc lib is loaded
                return new RpMallocGlobalPool().ToPool<T>();
            }
            //Use process heap
            else
            {
                return new ProcessHeap().ToPool<T>();
            }
        }

        private class RpMallocGlobalPool : IUnmangedHeap
        {
            IntPtr IUnmangedHeap.Alloc(ulong elements, ulong size, bool zero)
            {
                return RpMallocPrivateHeap.RpMalloc(elements, (nuint)size, zero);
            }

            bool IUnmangedHeap.Free(ref IntPtr block)
            {
                RpMallocPrivateHeap.RpFree(ref block);
                return true;
            }

            void IUnmangedHeap.Resize(ref IntPtr block, ulong elements, ulong size, bool zero)
            {
                throw new NotImplementedException();
            }

            public void Dispose()
            { }
        }
    }
}
