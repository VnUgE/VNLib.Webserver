using System;
using System.Linq;

using Serilog;
using Serilog.Core;
using Serilog.Events;

using VNLib.Utils;
using VNLib.Utils.Logging;

namespace VNLib.WebServer
{
    public class VLogProvider : VnDisposeable, ILogProvider
    {
        private readonly Logger LogCore;

        public VLogProvider(LoggerConfiguration config)
        {
            LogCore = config.CreateLogger();
        }
        public void Flush(){}

        public object GetLogProvider() => LogCore;

        public void Write(LogLevel level, string value)
        {
            LogCore.Write((LogEventLevel)level, value);
        }

        public void Write(LogLevel level, Exception exception, string value = "")
        {
            LogCore.Write((LogEventLevel)level, exception, value);
        }

        public void Write(LogLevel level, string value, params object[] args)
        {
            LogCore.Write((LogEventLevel)level, value, args);
        }

        public void Write(LogLevel level, string value, params ValueType[] args)
        {
            //Serilog logger supports passing valuetypes to avoid boxing objects
            if(LogCore.IsEnabled((LogEventLevel)level))
            {
                object[] ar = args.Select(a => (object)a).ToArray();
                LogCore.Write((LogEventLevel)level, value, ar);
            }
        }

        protected override void Free() => LogCore.Dispose();
    }
}
