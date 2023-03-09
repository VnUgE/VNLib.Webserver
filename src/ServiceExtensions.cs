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

        public static object? TryRegsiterForService(this IManagedPlugin plugin, Type serviceType, Action<object?> onUnload, object? state)
        {
            //Try to get the desired service
            object? service = plugin.Services.GetService(serviceType);

            if (service != null)
            {
                _ = new Registration(plugin, onUnload, state);
            }

            return service;
        }

        private sealed class Registration
        {
            private readonly CancellationTokenRegistration _reg;
            private readonly Action<object?> _callback;


            public Registration(IManagedPlugin plugin, Action<object?> callback, object? state)
            {
                _callback = callback;

                //Register unload token callback
                _reg = plugin.Services.UnloadToken.Register(OnCancelled, state, false);
            }


            void OnCancelled(object? state)
            {
                //Unregister the token
                using (_reg)
                {
                    //Invoke callback
                    _callback.Invoke(state);
                }
            }
        }
    }
}