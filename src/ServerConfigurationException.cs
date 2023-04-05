/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: Entry.cs 
*
* Entry.cs is part of VNLib.WebServer which is part of the larger 
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

/*
* Arguments
* --config <config_path>
* -v --verbose
* -d --debug
* -vv double verbose mode (logs all app-domain events)
* -s --silent silent logging mode, does not print logs to the console, only to output files
* --log-http prints raw http requests to the application log
* --rpmalloc to force enable the rpmalloc library loading for the Memory class
* --no-plugins disables plugin loading
* -t --threads specify the number of accept threads
*/


namespace VNLib.WebServer
{
    public class ServerConfigurationException : Exception
    {
        public ServerConfigurationException()
        {}

        public ServerConfigurationException(string? message) : base(message)
        {}

        public ServerConfigurationException(string? message, Exception? innerException) : base(message, innerException)
        {}
    }
}
