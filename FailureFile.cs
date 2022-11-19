/*
* Copyright (c) 2022 Vaughn Nugent
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

using VNLib.Utils.IO;

namespace VNLib.WebServer
{
    /// <summary>
    /// File the server will keep in memory and return to user when a specified error code is requested
    /// </summary>
    internal class FailureFile : InMemoryTemplate
    {
        public readonly HttpStatusCode Code;
       
        /// <summary>
        /// Returns refrence to a buffer contating the file data
        /// </summary>
        /// <exception cref="IOException"></exception>
        public Stream File => GetTemplateData();

        public override string TemplateName { get; }

        //Preloads failure files

        /// <summary>
        /// Catch an http error code and return the selected file to user
        /// </summary>
        /// <param name="code">Http status code to catch</param>
        /// <param name="file_path">Path to file contating data to return to use on status code</param>
        public FailureFile(HttpStatusCode code, string file_path):base(file_path, true)
        {
            Code = code;
        }
        //Nothing needs to changed when the file is modified
        protected override void OnModifed(){}
    }
}