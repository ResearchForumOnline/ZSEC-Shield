using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace TalkToAI.ZsecBrowserPreview
{
    internal sealed class BrowserAutomationRequest
    {
        public string Token { get; set; }
        public string Command { get; set; }
        public string Url { get; set; }
    }

    internal sealed class BrowserAutomationResponse
    {
        public bool Ok { get; set; }
        public string Error { get; set; }
        public string Version { get; set; }
        public int TabCount { get; set; }
        public int ActiveTab { get; set; }
        public bool WindowVisible { get; set; }
        public bool AutomationEnabled { get; set; }
        public bool RuntimeReady { get; set; }
    }

    internal static class BrowserLocalAutomationPolicy
    {
        internal const int MaximumMessageCharacters = 4096;

        internal static bool IsSupportedCommand(string command)
        {
            return String.Equals(command, "ping", StringComparison.Ordinal) ||
                String.Equals(command, "get_state", StringComparison.Ordinal) ||
                String.Equals(command, "open_url", StringComparison.Ordinal) ||
                String.Equals(command, "open_tab", StringComparison.Ordinal) ||
                String.Equals(command, "activate", StringComparison.Ordinal);
        }

        internal static bool TryNormalizeUrl(string candidate, out string normalized)
        {
            normalized = null;
            if (String.IsNullOrWhiteSpace(candidate) || candidate.Length > 2048) return false;
            Uri uri;
            if (!Uri.TryCreate(candidate, UriKind.Absolute, out uri)) return false;
            if (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) return false;
            if (!String.IsNullOrEmpty(uri.UserInfo)) return false;
            normalized = uri.AbsoluteUri;
            return true;
        }

        internal static bool FixedTimeTokenEquals(string expected, string supplied)
        {
            if (String.IsNullOrEmpty(expected) || String.IsNullOrEmpty(supplied)) return false;
            byte[] left = Encoding.UTF8.GetBytes(expected);
            byte[] right = Encoding.UTF8.GetBytes(supplied);
            if (left.Length != right.Length) return false;
            int difference = 0;
            for (int index = 0; index < left.Length; index++) difference |= left[index] ^ right[index];
            return difference == 0;
        }
    }

    internal sealed class BrowserLocalAutomationServer : IDisposable
    {
        private readonly Func<BrowserAutomationRequest, BrowserAutomationResponse> handler;
        private readonly string token;
        private readonly string pipeName;
        private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
        private Thread listener;

        internal BrowserLocalAutomationServer(
            string pipeName,
            string token,
            Func<BrowserAutomationRequest, BrowserAutomationResponse> handler
        )
        {
            this.pipeName = pipeName;
            this.token = token;
            this.handler = handler;
        }

        internal void Start()
        {
            listener = new Thread(Listen) { IsBackground = true, Name = "ZSEC local automation" };
            listener.Start();
        }

        private void Listen()
        {
            while (!cancellation.IsCancellationRequested)
            {
                try
                {
                    using (NamedPipeServerStream pipe = CreateCurrentUserPipe(pipeName))
                    {
                        pipe.WaitForConnection();
                        HandleConnection(pipe);
                    }
                }
                catch (IOException) { }
                catch (ObjectDisposedException) { }
            }
        }

        private void HandleConnection(Stream pipe)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = BrowserLocalAutomationPolicy.MaximumMessageCharacters };
            using (StreamReader reader = new StreamReader(pipe, new UTF8Encoding(false, true), false, 1024, true))
            using (StreamWriter writer = new StreamWriter(pipe, new UTF8Encoding(false), 1024, true) { AutoFlush = true })
            {
                string line = ReadBoundedLine(reader);
                BrowserAutomationResponse response;
                try
                {
                    BrowserAutomationRequest request = serializer.Deserialize<BrowserAutomationRequest>(line);
                    if (request == null || !BrowserLocalAutomationPolicy.FixedTimeTokenEquals(token, request.Token))
                        response = new BrowserAutomationResponse { Ok = false, Error = "unauthorized" };
                    else if (!BrowserLocalAutomationPolicy.IsSupportedCommand(request.Command))
                        response = new BrowserAutomationResponse { Ok = false, Error = "unsupported_command" };
                    else
                    {
                        try { response = handler(request); }
                        catch (Exception exception)
                        {
                            response = new BrowserAutomationResponse
                            {
                                Ok = false,
                                Error = "command_failed_" + exception.GetType().Name.ToLowerInvariant()
                            };
                        }
                    }
                }
                catch
                {
                    response = new BrowserAutomationResponse { Ok = false, Error = "invalid_request" };
                }
                writer.WriteLine(serializer.Serialize(response));
            }
        }

        private static string ReadBoundedLine(TextReader reader)
        {
            StringBuilder value = new StringBuilder();
            while (value.Length <= BrowserLocalAutomationPolicy.MaximumMessageCharacters)
            {
                int character = reader.Read();
                if (character < 0 || character == '\n') break;
                if (character != '\r') value.Append((char)character);
            }
            if (value.Length > BrowserLocalAutomationPolicy.MaximumMessageCharacters) throw new InvalidDataException();
            return value.ToString();
        }

        internal static NamedPipeServerStream CreateCurrentUserPipe(string name)
        {
            SecurityIdentifier current = WindowsIdentity.GetCurrent().User;
            PipeSecurity security = new PipeSecurity();
            security.SetOwner(current);
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new PipeAccessRule(current, PipeAccessRights.ReadWrite, AccessControlType.Allow));
            return new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.None, 4096, 4096, security);
        }

        public void Dispose()
        {
            cancellation.Cancel();
            try
            {
                using (NamedPipeClientStream wake = new NamedPipeClientStream(".", pipeName, PipeDirection.Out))
                { wake.Connect(100); }
            }
            catch { }
        }
    }

    internal static class BrowserAutomationToken
    {
        internal static string CreateSessionToken()
        {
            byte[] bytes = new byte[32];
            using (RandomNumberGenerator random = RandomNumberGenerator.Create()) random.GetBytes(bytes);
            StringBuilder value = new StringBuilder(64);
            foreach (byte item in bytes) value.Append(item.ToString("x2"));
            return value.ToString();
        }
    }
}
