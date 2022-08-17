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