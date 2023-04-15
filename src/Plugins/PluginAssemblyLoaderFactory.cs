/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: PluginAssemblyLoaderFactory.cs 
*
* PluginAssemblyLoaderFactory.cs is part of VNLib.WebServer which is 
* part of the larger VNLib collection of libraries and utilities.
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

using VNLib.Plugins.Runtime;
using VNLib.Plugins.Essentials.ServiceStack;

namespace VNLib.WebServer.Plugins
{
    internal sealed record class PluginAssemblyLoaderFactory(Func<string, PlugingAssemblyConfig> ConfigFactory) : IPluginAssemblyLoaderFactory
    {
        public IPluginAssemblyLoader GetLoaderForPluginFile(string pluginFile)
        {
            //Create new loader from asm path
            PlugingAssemblyConfig config = ConfigFactory(pluginFile);

            return new PluginAssemblyLoader(config);
        }
    }
}
