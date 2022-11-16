using System.Collections.Generic;
using System.Linq;

namespace VNLib.WebServer.RuntimeLoading
{
    internal class ProcessArguments
    {
        private readonly List<string> _args;

        public ProcessArguments(string[] args) => _args = args.ToList();

        public bool HasArg(string arg) => _args.Contains(arg);

        public bool Verbose => HasArg("-v") || HasArg("--verbose");
        public bool Debug => HasArg("-d") || HasArg("--debug");
        public bool Silent => HasArg("-s") || HasArg("--silent");
        public bool RpMalloc => HasArg("--rpmalloc");
        public bool DoubleVerbose => Verbose && HasArg("-vv");

        public bool LogHttp => HasArg("--log-http");

        /// <summary>
        /// Gets the value following the specified argument, or 
        /// null no value follows the specified argument
        /// </summary>
        /// <param name="arg"></param>
        /// <returns></returns>
        public string? GetArg(string arg)
        {
            int index = _args.IndexOf(arg);
            return index == -1 || index + 1 >= _args.Count ? null : _args[index + 1];
        }
    }
}
