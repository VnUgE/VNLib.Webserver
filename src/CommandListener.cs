/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: CommandListener.cs 
*
* CommandListener.cs is part of VNLib.WebServer which is part of 
* the larger VNLib collection of libraries and utilities.
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
using System.Threading;

using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Utils.Memory.Diagnostics;
using VNLib.Net.Http;
using VNLib.Plugins.Essentials.ServiceStack;
using VNLib.Plugins.Essentials.ServiceStack.Plugins;

using VNLib.WebServer.Bootstrap;

namespace VNLib.WebServer
{
    internal sealed class CommandListener(TextReader input, TextWriter output, ILogProvider log)
    {
        const string MANAGED_HEAP_STATS = @"
         Managed Heap Stats
--------------------------------------
 Collections: 
   Gen0: {g0} Gen1: {g1} Gen2: {g2}

 Heap:
  High Watermark:    {hw} KB
  Last GC Heap Size: {hz} KB
  Current Load:      {ld} KB
  Fragmented:        {fb} KB

 Heap Info:
  Last GC concurrent? {con}
  Last GC compacted?  {comp}
  Pause time:         {pt} %
  Pending finalizers: {pf}
  Pinned objects:     {po}
";

        const string HEAPSTATS = @"
    Unmanaged Heap Stats
---------------------------
 userHeap? {rp}
 Allocated bytes:   {ab}
 Allocated handles: {h}
 Max block size:    {mb}
 Min block size:    {mmb}
 Max heap size:     {hs}
";

        private readonly TextReader _input = input;
        private readonly TextWriter _output = output;

        /// <summary>
        /// Listens for commands and processes them in a continuous loop
        /// </summary>
        /// <param name="shutdownEvent">A <see cref="ManualResetEvent"/> that is set when the Stop command is received</param>
        /// <param name="server">The webserver for the current process</param>
        public void ListenForCommands(ManualResetEvent shutdownEvent, WebserverBase server)
        {
            HttpServiceStack serviceStack = server.ServiceStack;

            log.Information("Listening for commands on stdin");

            while (shutdownEvent.WaitOne(0) == false)
            {
                string[]? s = _input.ReadLine()?.Split(' ');
                if (s == null)
                {
                    continue;
                }
                switch (s[0].ToLower(null))
                {
                    //handle plugin
                    case "p":
                        {
                            if (s.Length < 3)
                            {
                                _output.WriteLine("Plugin name and command are required");
                                break;
                            }

                            string message = string.Join(' ', s[2..]);

                            bool sent = serviceStack.PluginManager.SendCommandToPlugin(s[1], message, StringComparison.OrdinalIgnoreCase);

                            if (!sent)
                            {
                                _output.WriteLine("Plugin not found");
                            }
                        }
                        break;

                    case "cmd":
                        {
                            if (s.Length < 2)
                            {
                                _output.WriteLine("Plugin name is required");
                                break;
                            }

                            //Enter plugin command loop
                            EnterPluginLoop(s[1], serviceStack.PluginManager);
                        }
                        break;
                    case "reload":
                        {
                            try
                            {
                                //Reload all plugins
                                serviceStack.PluginManager.ForceReloadAllPlugins();
                            }
                            catch (Exception ex)
                            {
                                log.Error(ex);
                            }
                        }
                        break;
                    case "memstats":
                        {


                            //Collect gc info for managed heap stats
                            int gen0 = GC.CollectionCount(0);
                            int gen1 = GC.CollectionCount(1);
                            int gen2 = GC.CollectionCount(2);
                            GCMemoryInfo mi = GC.GetGCMemoryInfo();

                            log.Debug(MANAGED_HEAP_STATS,
                                gen0,
                                gen1,
                                gen2,
                                mi.HighMemoryLoadThresholdBytes / 1024,
                                mi.HeapSizeBytes / 1024,
                                mi.MemoryLoadBytes / 1024,
                                mi.FragmentedBytes / 1024,
                                mi.Concurrent,
                                mi.Compacted,
                                mi.PauseTimePercentage,
                                mi.FinalizationPendingCount,
                                mi.PinnedObjectsCount
                            );

                            //Get heap stats
                            HeapStatistics hs = MemoryUtil.GetSharedHeapStats();

                            //Print unmanaged heap stats
                            log.Debug(HEAPSTATS,
                                MemoryUtil.IsUserDefinedHeap,
                                hs.AllocatedBytes,
                                hs.AllocatedBlocks,
                                hs.MaxBlockSize,
                                hs.MinBlockSize,
                                hs.MaxHeapSize
                            );
                        }
                        break;
                    case "collect":
                        CollectCache(serviceStack);
                        GC.Collect(2, GCCollectionMode.Forced, false, true);
                        GC.WaitForFullGCComplete();
                        break;
                    case "stop":
                        shutdownEvent.Set();
                        return;
                }
            }
        }

        /*
         * Function scopes commands as if the user is writing directly to 
         * the plugin. All commands are passed to the plugin manager for
         * processing.
         */
        private void EnterPluginLoop(string pluignName, IHttpPluginManager man)
        {
            _output.WriteLine("Entering plugin {0}. Type 'exit' to leave", pluignName);

            while (true)
            {
                _output.Write("{0}>", pluignName);

                string? input = _input.ReadLine();

                if (string.IsNullOrWhiteSpace(input))
                {
                    _output.WriteLine("Please enter a command or type 'exit' to leave");
                    continue;
                }

                if (input.AsSpan().Trim().Equals("exit", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                //Exec command
                if (!man.SendCommandToPlugin(pluignName, input, StringComparison.OrdinalIgnoreCase))
                {
                    _output.WriteLine("Plugin does not exist exiting loop");
                    break;
                }
            }
        }

        private static void CollectCache(HttpServiceStack controller) 
            => controller.Servers.ForEach(static server => (server as HttpServer)!.CacheClear());

        public static CommandListener FromConsole(ILogProvider log)
        { 
            return new(
                input: Console.In, 
                output: Console.Out, 
                log
            );
        }
    }
}
