using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

using Serilog;

using VNLib.Utils.Extensions;

#nullable enable

namespace VNLib.WebServer.RuntimeLoading
{
    internal class ServerLogBuilder
    {
        public LoggerConfiguration SysLogConfig { get; }
        public LoggerConfiguration AppLogConfig { get; }
        public LoggerConfiguration? DebugConfig { get; }

        public ServerLogBuilder()
        {
            AppLogConfig = new();
            SysLogConfig = new();
        }

        public ServerLogBuilder BuildForConsole(ProcessArguments args)
        {
            InitConsoleLog(args, AppLogConfig, "Application");
            InitConsoleLog(args, SysLogConfig, "System");
            return this;
        }

        public ServerLogBuilder BuildFromConfig(in JsonElement logEl)
        {
            InitSingleLog(in logEl, "app_log", "Application", AppLogConfig);
            InitSingleLog(in logEl, "sys_log", "System", SysLogConfig);
            return this;
        }

        public ServerLogger GetLogger()
        {
            //build providers
            VLogProvider appLog = new(AppLogConfig);
            VLogProvider sysLog = new(SysLogConfig);
            VLogProvider? debugLog = DebugConfig == null ? null : new(DebugConfig);
            //Return logger
            return new ServerLogger(appLog, sysLog, debugLog);
        }

        private static void InitConsoleLog(ProcessArguments args, LoggerConfiguration conf, string logName)
        {
            //Set verbosity level, defaul to informational
            if (args.Debug)
            {
                conf.MinimumLevel.Verbose();
            }
            else if (args.Verbose)
            {
                conf.MinimumLevel.Debug();
            }
            else
            {
                conf.MinimumLevel.Information();
            }

            //Setup loggers to write to console unless the -s silent arg is set
            if (!args.Silent)
            {
                string template = $"{{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz}} [{{Level:u3}}] {logName} {{Message:lj}}{{NewLine}}{{Exception}}";
                _ = conf.WriteTo.Console(outputTemplate: template);
            }
        }

        private static void InitSingleLog(in JsonElement el, string elPath, string logName, LoggerConfiguration logConfig)
        {
            string? filePath = null;
            string? template = null;

            TimeSpan flushInterval = TimeSpan.FromSeconds(2);
            int retainedLogs = 31;
            //Default to 500mb log file size
            int fileSizeLimit = 500 * 1000 * 1024;
            RollingInterval interval = RollingInterval.Infinite;

            //try to get the log config object
            if (el.TryGetProperty(elPath, out JsonElement logEl))
            {
                IReadOnlyDictionary<string, JsonElement> conf = logEl.EnumerateObject().ToDictionary(s => s.Name, s => s.Value);

                filePath = conf.GetPropString("path");
                template = conf.GetPropString("template");

                if (conf.TryGetValue("flush_sec", out JsonElement flushEl))
                {
                    flushInterval = flushEl.GetTimeSpan(TimeParseType.Seconds);
                }

                if (conf.TryGetValue("retained_files", out JsonElement retainedEl))
                {
                    retainedLogs = retainedEl.GetInt32();
                }

                if (conf.TryGetValue("file_size_limit", out JsonElement sizeEl))
                {
                    fileSizeLimit = sizeEl.GetInt32();
                }

                if (conf.TryGetValue("interval", out JsonElement intervalEl))
                {
                    interval = Enum.Parse<RollingInterval>(intervalEl.GetString()!, true);
                }
            }
            //Set default objects
            filePath ??= Path.Combine(Environment.CurrentDirectory, $"{elPath}.txt");
            template ??= $"{{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz}} [{{Level:u3}}] {logName} {{Message:lj}}{{NewLine}}{{Exception}}";
            //Configure the log file writer
            logConfig.WriteTo.File(filePath, buffered: true, retainedFileCountLimit: retainedLogs, fileSizeLimitBytes: fileSizeLimit, rollingInterval: interval, outputTemplate: template);
        }
    }
}
