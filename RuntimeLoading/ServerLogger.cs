using System.Text;
using System.Threading.Tasks;

using VNLib.Utils;

#nullable enable

namespace VNLib.WebServer.RuntimeLoading
{
    internal class ServerLogger : VnDisposeable
    {

        public VLogProvider AppLog { get; }

        public VLogProvider SysLog { get; }

        public VLogProvider? DebugLog { get; }

        public ServerLogger(VLogProvider applog, VLogProvider syslog, VLogProvider? debuglog)
        {
            AppLog = applog;
            SysLog = syslog;
            DebugLog = debuglog;
        }

        protected override void Free()
        {
            AppLog.Dispose();
            SysLog.Dispose();
            DebugLog?.Dispose();
        }
    }
}
