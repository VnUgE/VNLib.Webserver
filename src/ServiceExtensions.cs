/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: ServiceExtensions.cs 
*
* ServiceExtensions.cs is part of VNLib.WebServer which is part of the larger 
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
using System.Threading;

using VNLib.Plugins.Essentials.ServiceStack;

namespace VNLib.WebServer
{
    internal static class ServiceExtensions
    {       

        public static object? TryRegsiterForService<T>(this IManagedPlugin plugin, Type serviceType, Action<T?> onUnload, T? state)
        {
            //Try to get the desired service
            object? service = plugin.Services.GetService(serviceType);

            if (service != null)
            {
                _ = new Registration<T>(plugin, onUnload, state);
            }

            return service;
        }

        public static object? TryRegsiterForService<T>(this IManagedPlugin plugin, Type serviceType, Action<T?, object> onUnload, T? state)
        {
            //Try to get the desired service
            object? service = plugin.Services.GetService(serviceType);

            if (service != null)
            {
                _ = new Registration<T>(plugin, (s) => onUnload(s, service), state);
            }

            return service;
        }

        private class Registration<T>
        {
            private readonly CancellationTokenRegistration _reg;
            private readonly Action<T?> _callback;


            public Registration(IManagedPlugin plugin, Action<T?> callback, T? state)
            {
                _callback = callback;

                //Register unload token callback
                _reg = plugin.Services.UnloadToken.Register(OnCancelled, state, false);
            }


            protected void OnCancelled(object? state)
            {
                //Unregister the token
                using (_reg)
                {
                    //Invoke callback
                    _callback.Invoke((T?)state);
                }
            }
        }
    }
}