//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Net;
using CoreFoundation;
using Foundation;

namespace Microsoft.IdentityService.Clients.ActiveDirectory
{
    static class UrlRequestHeaders
    {
        /// <summary>
        /// Adds Basic auth proxy header for a https request.
        /// </summary>
        public static void AddProxyHeader(NSMutableUrlRequest request)
        {
            if (!StringComparer.OrdinalIgnoreCase.Equals(request.Url.Scheme, "https"))
                return;

            ProxyInfo proxy = GetProxy(request.Url);
            if (proxy == null || proxy.ProxyType != CFProxyType.HTTPS)
                return;

            NSUrlCredential credential = GetProxyCredential(proxy);
            if (credential == null)
                return;

            string auth = GetBasicAuthHeaderValue(credential);
            if (string.IsNullOrEmpty(auth))
                return;

            var headers = new NSMutableDictionary();
            headers["Proxy-Authorization"] = new NSString(auth);
            foreach (var header in request.Headers)
            {
                headers[header.Key] = header.Value;
            }
            request.Headers = headers;
        }

        static ProxyInfo GetProxy(Uri requestUri)
        {
            IWebProxy systemProxy = WebRequest.GetSystemWebProxy();
            Uri proxyUri = systemProxy.GetProxy(requestUri);
            var proxyAddress = new Uri(proxyUri.AbsoluteUri);

            if (string.Equals(proxyAddress.AbsoluteUri, requestUri.AbsoluteUri))
                return null;
            if (systemProxy.IsBypassed(requestUri))
                return null;

            return new ProxyInfo
            {
                Port = proxyAddress.Port,
                ProxyType = GetProxyType(requestUri),
                HostName = proxyAddress.Host
            };
        }

        static CFProxyType GetProxyType(Uri requestUri)
        {
            switch (requestUri.Scheme.ToLower())
            {
                case "https":
                    return CFProxyType.HTTPS;
                case "http":
                    return CFProxyType.HTTP;
                default:
                    return CFProxyType.None;
            }
        }

        static NSUrlCredential GetProxyCredential(ProxyInfo proxy)
        {
            foreach (NSObject key in NSUrlCredentialStorage.SharedCredentialStorage.AllCredentials.Keys)
            {
                var protectionSpace = key as NSUrlProtectionSpace;
                if (!IsProtectionSpaceForProject(protectionSpace, proxy))
                    continue;

                // Only basic auth is supported.
                if (protectionSpace.AuthenticationMethod != NSUrlProtectionSpace.AuthenticationMethodHTTPBasic)
                    continue;

                var dictionary = NSUrlCredentialStorage.SharedCredentialStorage.AllCredentials[key] as NSDictionary;
                if (dictionary == null)
                    continue;

                foreach (var value in dictionary)
                {
                    var credential = value.Value as NSUrlCredential;
                    if (credential != null)
                        return credential;
                }
            }
            return null;
        }

        static bool IsProtectionSpaceForProject(NSUrlProtectionSpace protectionSpace, ProxyInfo proxy)
        {
            return protectionSpace != null &&
                protectionSpace.IsProxy &&
                protectionSpace.Port == proxy.Port &&
                StringComparer.OrdinalIgnoreCase.Equals(protectionSpace.ProxyType, proxy.ProxyType.ToString()) &&
                StringComparer.OrdinalIgnoreCase.Equals(protectionSpace.Host, proxy.HostName);
        }

       static string GetBasicAuthHeaderValue(NSUrlCredential credential)
        {
            if (string.IsNullOrEmpty(credential.User))
                return null;

            string password = credential.Password ?? string.Empty;
            byte[] bytes = GetBytes(credential.User + ":" + password);

            return "Basic " + Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// From Mono's BasicClient
        /// </summary>
        static byte[] GetBytes(string str)
        {
            int i = str.Length;
            byte[] result = new byte[i];
            for (--i; i >= 0; i--)
                result[i] = (byte)str[i];

            return result;
        }
    }
}
