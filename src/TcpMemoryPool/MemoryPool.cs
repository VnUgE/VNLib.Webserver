/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: MemoryPool.cs 
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
            //Use the shared heap impl. which also allows diagnostics, and is tuned
            return MemoryUtil.Shared.ToPool<T>();
        }
    }
}
