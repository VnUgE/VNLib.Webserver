/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: FailureFile.cs 
*
* FailureFile.cs is part of VNLib.WebServer which is part of the larger 
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
using System.IO;
using System.Net;

using VNLib.Net.Http;
using VNLib.Utils.IO;

namespace VNLib.WebServer
{
    /// <summary>
    /// File the server will keep in memory and return to user when a specified error code is requested
    /// </summary>
    internal class FailureFile : InMemoryTemplate
    {
        public readonly HttpStatusCode Code;

        private Lazy<byte[]> _templateData;

        public override string TemplateName { get; }       

        /// <summary>
        /// Catch an http error code and return the selected file to user
        /// </summary>
        /// <param name="code">Http status code to catch</param>
        /// <param name="filePath">Path to file contating data to return to use on status code</param>
        public FailureFile(HttpStatusCode code, string filePath):base(filePath, true)
        {
            Code = code;
            _templateData = new(LoadTemplateData);
            TemplateName = filePath;
        }
        
        //Nothing needs to changed when the file is modified
        protected override void OnModifed()
        {
            //Update lazy loader for new file update
            _templateData = new(LoadTemplateData);
        }

        private byte[] LoadTemplateData()
        {
            //Get file data as binary
            return File.ReadAllBytes(TemplateFile.FullName);
        }

        /// <summary>
        /// Gets a <see cref="IMemoryResponseReader"/> wrapper that may read a copy of the 
        /// file representation
        /// </summary>
        /// <returns>The <see cref="IMemoryResponseReader"/> wrapper around the file data</returns>
        public IMemoryResponseReader GetReader() => new MemReader(_templateData.Value);

        private class MemReader : IMemoryResponseReader
        {
            private readonly byte[] _memory;

            private int _written;

            public int Remaining { get; private set; }

            internal MemReader(byte[] data)
            {
                //Store ref as memory
                _memory = data;
                Remaining = data.Length;
            }

            public void Advance(int written)
            {
                _written += written;
                Remaining -= written;
            }

            void IMemoryResponseReader.Close() { }

            ReadOnlyMemory<byte> IMemoryResponseReader.GetMemory() => _memory.AsMemory(_written, Remaining);
        }
    }
}