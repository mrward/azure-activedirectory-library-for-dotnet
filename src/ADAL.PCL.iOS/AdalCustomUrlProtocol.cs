//----------------------------------------------------------------------
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
using CoreFoundation;
using Foundation;
#if MAC
using ObjCRuntime;
using System.Runtime.InteropServices;
using INSUrlProtocolClient = Microsoft.IdentityService.Clients.ActiveDirectory.CustomNSUrlProtocolClient;
#endif

namespace Microsoft.IdentityService.Clients.ActiveDirectory
{
    internal class AdalCustomUrlProtocol : NSUrlProtocol
    {
        private NSUrlConnection connection;

        [Export("canInitWithRequest:")]
        public static bool canInitWithRequest(NSUrlRequest request)
        {
            if (request.Url.Scheme.Equals("https", StringComparison.CurrentCultureIgnoreCase))
            {
                return GetProperty("ADURLProtocol", request) == null;
            }

            return false;
        }

        [Export("canonicalRequestForRequest:")]
        public new static NSUrlRequest GetCanonicalRequest(NSUrlRequest request)
        {
            return request;
        }

        [Export("initWithRequest:cachedResponse:client:")]
        public AdalCustomUrlProtocol(NSUrlRequest request, NSCachedUrlResponse cachedResponse,
#if MAC
            Foundation.NSUrlProtocolClient client)
#else
            INSUrlProtocolClient client)
#endif
            : base(request, cachedResponse, client)
        {
        }

        public override void StartLoading()
        {
            if (this.Request == null)
            {
                return;
            }

            NSMutableUrlRequest mutableRequest = (NSMutableUrlRequest) this.Request.MutableCopy();
            SetProperty(new NSString("YES"), "ADURLProtocol", mutableRequest);
            this.connection = new NSUrlConnection(mutableRequest, new AdalCustomConnectionDelegate(this), true);
        }

        public override void StopLoading()
        {
            this.connection.Cancel();
        }

        private class AdalCustomConnectionDelegate : NSUrlConnectionDataDelegate
        {
            private AdalCustomUrlProtocol handler;
            private INSUrlProtocolClient client;

            public AdalCustomConnectionDelegate(AdalCustomUrlProtocol handler)
            {
                this.handler = handler;
#if MAC
                client = new CustomNSUrlProtocolClient (handler.WeakClient.Handle);
#else
                client = handler.Client;
#endif
            }

            public override void ReceivedData(NSUrlConnection connection, NSData data)
            {
                client.DataLoaded(handler, data);
            }

            public override void FailedWithError(NSUrlConnection connection, NSError error)
            {
                client.FailedWithError(handler, error);
                connection.Cancel();
            }

            public override void ReceivedResponse(NSUrlConnection connection, NSUrlResponse response)
            {
                client.ReceivedResponse(handler, response, NSUrlCacheStoragePolicy.NotAllowed);
            }

            public override NSUrlRequest WillSendRequest(NSUrlConnection connection, NSUrlRequest request,
                NSUrlResponse response)
            {
                NSMutableUrlRequest mutableRequest = (NSMutableUrlRequest) request.MutableCopy();
                if (response != null)
                {
                    RemoveProperty("ADURLProtocol", mutableRequest);
                    client.Redirected(handler, mutableRequest, response);
                    connection.Cancel();
                    if (!request.Headers.ContainsKey(new NSString("x-ms-PkeyAuth")))
                    {
                        mutableRequest[BrokerConstants.ChallengeHeaderKey] = BrokerConstants.ChallengeHeaderValue;
                    }
                    return mutableRequest;
                }

                if (!request.Headers.ContainsKey(new NSString(BrokerConstants.ChallengeHeaderKey)))
                {
                    mutableRequest[BrokerConstants.ChallengeHeaderKey] = BrokerConstants.ChallengeHeaderValue;
                }

                return mutableRequest;
            }

            public override void FinishedLoading(NSUrlConnection connection)
            {
                client.FinishedLoading(handler);
                connection.Cancel();
            }
        }
    }
#if MAC
    class CustomNSUrlProtocolClient : IDisposable
    {
        IntPtr handle;

        public IntPtr Handle { get { return handle; } }

        public CustomNSUrlProtocolClient (IntPtr handle)
        {
            this.handle = handle;
            DangerousRetain (handle);
        }

        ~CustomNSUrlProtocolClient ()
        {
            Dispose ();
        }

        public void Dispose ()
        {
            if (handle != IntPtr.Zero) {
                DangerousRelease (handle);
                handle = IntPtr.Zero;
            }
        }

        internal static void DangerousRelease (IntPtr handle)
        {
            if (handle == IntPtr.Zero)
                return;
            Messaging.void_objc_msgSend (handle, Selector.GetHandle ("release"));
        }

        internal static void DangerousRetain (IntPtr handle)
        {
            if (handle == IntPtr.Zero)
                return;
            Messaging.void_objc_msgSend (handle, Selector.GetHandle ("retain"));
        }

        const string selUrlProtocolWasRedirectedToRequestRedirectResponse_ = "URLProtocol:wasRedirectedToRequest:redirectResponse:";
        const string selUrlProtocolCachedResponseIsValid_ = "URLProtocol:cachedResponseIsValid:";
        const string selUrlProtocolDidReceiveResponseCacheStoragePolicy_ = "URLProtocol:didReceiveResponse:cacheStoragePolicy:";
        const string selUrlProtocolDidLoadData_ = "URLProtocol:didLoadData:";
        const string selUrlProtocolDidFinishLoading_ = "URLProtocolDidFinishLoading:";
        const string selUrlProtocolDidFailWithError_ = "URLProtocol:didFailWithError:";
        const string selUrlProtocolDidReceiveAuthenticationChallenge_ = "URLProtocol:didReceiveAuthenticationChallenge:";
        const string selUrlProtocolDidCancelAuthenticationChallenge_ = "URLProtocol:didCancelAuthenticationChallenge:";

        public void Redirected (NSUrlProtocol protocol, NSUrlRequest redirectedToEequest, NSUrlResponse redirectResponse)
        {
            Messaging.void_objc_msgSend_IntPtr_IntPtr_IntPtr (this.Handle, Selector.GetHandle (selUrlProtocolWasRedirectedToRequestRedirectResponse_), protocol.Handle, redirectedToEequest.Handle, redirectResponse.Handle);
        }

        public void CachedResponseIsValid (NSUrlProtocol protocol, NSCachedUrlResponse cachedResponse)
        {
            Messaging.void_objc_msgSend_IntPtr_IntPtr (this.Handle, Selector.GetHandle (selUrlProtocolCachedResponseIsValid_), protocol.Handle, cachedResponse.Handle);
        }

        public void ReceivedResponse (NSUrlProtocol protocol, NSUrlResponse response, NSUrlCacheStoragePolicy policy)
        {
            Messaging.void_objc_msgSend_IntPtr_IntPtr_int (this.Handle, Selector.GetHandle (selUrlProtocolDidReceiveResponseCacheStoragePolicy_), protocol.Handle, response.Handle, (int)policy);
        }

        public void DataLoaded (NSUrlProtocol protocol, NSData data)
        {
            Messaging.void_objc_msgSend_IntPtr_IntPtr (this.Handle, Selector.GetHandle (selUrlProtocolDidLoadData_), protocol.Handle, data.Handle);
        }

        public void FinishedLoading (NSUrlProtocol protocol)
        {
            Messaging.void_objc_msgSend_IntPtr (this.Handle, Selector.GetHandle (selUrlProtocolDidFinishLoading_), protocol.Handle);
        }

        public void FailedWithError (NSUrlProtocol protocol, NSError error)
        {
            Messaging.void_objc_msgSend_IntPtr_IntPtr (this.Handle, Selector.GetHandle (selUrlProtocolDidFailWithError_), protocol.Handle, error.Handle);
        }

        public void ReceivedAuthenticationChallenge (NSUrlProtocol protocol, NSUrlAuthenticationChallenge challenge)
        {
            Messaging.void_objc_msgSend_IntPtr_IntPtr (this.Handle, Selector.GetHandle (selUrlProtocolDidReceiveAuthenticationChallenge_), protocol.Handle, challenge.Handle);
        }

        public void CancelledAuthenticationChallenge (NSUrlProtocol protocol, NSUrlAuthenticationChallenge challenge)
        {
            Messaging.void_objc_msgSend_IntPtr_IntPtr (this.Handle, Selector.GetHandle (selUrlProtocolDidCancelAuthenticationChallenge_), protocol.Handle, challenge.Handle);
        }

        class Messaging {
            const string LIBOBJC_DYLIB = "/usr/lib/libobjc.dylib";
            [DllImport (LIBOBJC_DYLIB, EntryPoint="objc_msgSend")]
            public extern static void void_objc_msgSend (IntPtr receiver, IntPtr selector);
            [DllImport (LIBOBJC_DYLIB, EntryPoint="objc_msgSend")]
            public extern static void void_objc_msgSend_IntPtr_IntPtr_IntPtr (IntPtr receiver, IntPtr selector, IntPtr arg1, IntPtr arg2, IntPtr arg3);
            [DllImport (LIBOBJC_DYLIB, EntryPoint="objc_msgSend")]
            public extern static void void_objc_msgSend_IntPtr_IntPtr (IntPtr receiver, IntPtr selector, IntPtr arg1, IntPtr arg2);
            [DllImport (LIBOBJC_DYLIB, EntryPoint="objc_msgSend")]
            public extern static void void_objc_msgSend_IntPtr_IntPtr_int (IntPtr receiver, IntPtr selector, IntPtr arg1, IntPtr arg2, int arg3);
            [DllImport (LIBOBJC_DYLIB, EntryPoint="objc_msgSend")]
            public extern static void void_objc_msgSend_IntPtr (IntPtr receiver, IntPtr selector, IntPtr arg1);
        }
    }
#endif
}
