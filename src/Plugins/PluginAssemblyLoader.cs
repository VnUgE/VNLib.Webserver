/*
* Copyright (c) 2023 Vaughn Nugent
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
    internal sealed record class PluginAssemblyLoader(PlugingAssemblyConfig Config) : IPluginAssemblyLoader
    {
        ///<inheritdoc/>
        IPluginConfig IPluginAssemblyLoader.Config => Config;

        private PluginLoader? _loader;

        ///<inheritdoc/>
        public Assembly GetAssembly()
        {
            _ = _loader ?? throw new InvalidOperationException("The assembly loader was not loaded yet, you must call the Load method before you can call this method");
            return _loader.LoadDefaultAssembly();
        }

        ///<inheritdoc/>
        public void Load()
        {
            //Init a new loader if the old loader has been cleaned up, otherwise do nothing
            _loader ??= new(Config);
        }

        ///<inheritdoc/>
        public void Unload()
        {
            if (Config.Unloadable)
            {
                //Cleanup old loader
                _loader?.Dispose();
                _loader = null;
            }
        }

        public void Dispose() => Unload();
    }
}
