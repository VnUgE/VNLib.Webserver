/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: PluginAssemblyLoader.cs 
*
* PluginAssemblyLoader.cs is part of VNLib.WebServer which is part of the larger 
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
using System.Reflection;

using McMaster.NETCore.Plugins;

using VNLib.Plugins.Runtime;

namespace VNLib.WebServer.Plugins
{
    internal sealed record class PluginAssemblyLoader(IPluginAssemblyLoadConfig Config) : IAssemblyLoader
    {

        private readonly PluginLoader _loader = new(new(Config.AssemblyFile) { 
            PreferSharedTypes = true, 
            IsUnloadable = Config.Unloadable, 
            LoadInMemory = Config.Unloadable 
        });

        ///<inheritdoc/>
        public Assembly GetAssembly() => _loader.LoadDefaultAssembly();

        ///<inheritdoc/>
        public void Load() => _loader.Load();

        ///<inheritdoc/>
        public void Unload()
        {
            if (Config.Unloadable)
            {
                //Cleanup old loader, dont invoke GC because runtime will handle it
                _loader.Destroy(false);
            }
        }

        public void Dispose() => Unload();
    }
}
