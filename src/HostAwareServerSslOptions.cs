/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.WebServer
* File: HostAwareServerSslOptions.cs 
*
* HostAwareServerSslOptions.cs is part of VNLib.WebServer which is part 
* of the larger VNLib collection of libraries and utilities.
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
using System.Linq;
using System.Net.Security;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using VNLib.Plugins.Essentials.ServiceStack;


namespace VNLib.WebServer
{
    internal sealed class HostAwareServerSslOptions : SslServerAuthenticationOptions
    {
        //TODO programatically setup ssl protocols, but for now we only use HTTP/1.1 so this can be hard-coded
        internal static readonly List<SslApplicationProtocol> SslAppProtocols = new()
        {
            SslApplicationProtocol.Http11,
            //SslApplicationProtocol.Http2,
        };

        private readonly IReadOnlyDictionary<string, X509Certificate> _certByHost;
        private readonly HashSet<string> _certRequiredHosts;
        private readonly X509Certificate? _defaultCert;

        public HostAwareServerSslOptions(IReadOnlyCollection<IServiceHost> hosts, bool doNotForceTlsProtocols)
        {
            ArgumentNullException.ThrowIfNull(hosts, nameof(hosts));

            //Set validation callback
            RemoteCertificateValidationCallback = OnRemoteCertVerification;
            ServerCertificateSelectionCallback = OnGetCertificatForHost;

            //Get the vh configs from the transport info host config, all hosts passed to this constructor must all have certificates
            _certByHost = hosts.ToDictionary(static sh => sh.Processor.Hostname, static sh => sh.TransportInfo.Certificate!, StringComparer.OrdinalIgnoreCase);

            /*
             * See if any certificates require a client certificate to be valid
             * and only store the hostnames that require a client certificate in 
             * lookup set by hostname
             */
            _certRequiredHosts = _certByHost.Where(kvp => kvp.Value.IsClientCertRequired())
                .Select(kvp => kvp.Key)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);


            //Get the wildcard hostname as the default certificate
            _defaultCert = _certByHost.GetValueOrDefault("*");

            ConfigureBaseDefaults(doNotForceTlsProtocols);
        }

        private void ConfigureBaseDefaults(bool doNotForceProtocols)
        {
            //Eventually when HTTP2 is supported, we can select the ssl version to match
            ApplicationProtocols = SslAppProtocols;

            AllowRenegotiation = false;
            EncryptionPolicy = EncryptionPolicy.RequireEncryption;

            //Allow user to disable forced protocols and let the os decide
            EnabledSslProtocols = doNotForceProtocols ? SslProtocols.None : SslProtocols.Tls12 | SslProtocols.Tls13;
        }

        private bool OnRemoteCertVerification(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            /*
             * The ssl stream provides the hostname for the current context, we can use it to get the 
             * host configuration by it's hostname
             * 
             * Each host may required client certificate be valid, we can also use the wildcard cert here.
             * 
             * The default is not requiring a certificate
             */
            if (
                sender is SslStream ssl &&
                _certRequiredHosts.Contains(ssl.TargetHostName) ||
                _certRequiredHosts.Contains("*")
                )
            {
                return sslPolicyErrors == SslPolicyErrors.None;
            }

            return sslPolicyErrors == SslPolicyErrors.RemoteCertificateNotAvailable;
        }

        /*
         * Callback for getting the certificate from a hostname
         */
        private X509Certificate OnGetCertificatForHost(object sender, string? hostName) => _certByHost.GetValueOrDefault(hostName ?? "*", _defaultCert!)!;
    }
}
