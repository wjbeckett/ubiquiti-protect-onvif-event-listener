using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Renci.SshNet;

namespace OnvifRecorderInstaller.Services;

public sealed class ConnectResult {
    public bool Ok { get; init; }
    public string Fingerprint { get; init; } = "";
    public string Error { get; init; } = "";
    // True when the failure was a credential rejection (wrong password,
    // bad key, etc).  Distinguishes auth failures from network /
    // host-key / unreachable errors so the UI can apply an
    // auth-specific cooldown matching the server's faillock policy.
    public bool IsAuthFailure { get; init; }
}

public sealed class RunResult {
    public int ExitStatus { get; init; }
    public string Stdout { get; init; } = "";
    public string Stderr { get; init; } = "";
    public bool Ok => ExitStatus == 0;
}

// Thin wrapper around SSH.NET's SshClient. Each method opens a fresh
// connection, runs the command, and disposes — simpler than keeping a
// long-lived client around.
public sealed class SshService {
    public async Task<ConnectResult> TestConnectionAsync(
            Connection c, CancellationToken ct = default) {
        try {
            var (client, fingerprintHolder) = CreateClient(c);
            using (client) {
                await Task.Run(() => client.Connect(), ct).ConfigureAwait(false);
                using var cmd = client.CreateCommand("echo ok");
                var output = await Task.Run(() => cmd.Execute(), ct)
                                       .ConfigureAwait(false);
                client.Disconnect();
                var fp = fingerprintHolder.Value;
                return new ConnectResult {
                    Ok = output.Trim() == "ok" && cmd.ExitStatus == 0,
                    Fingerprint = fp,
                    Error = output.Trim() == "ok"
                        ? "" : $"unexpected response: {output.Trim()}",
                };
            }
        } catch (Renci.SshNet.Common.SshAuthenticationException ex) {
            return new ConnectResult {
                Ok = false,
                Error = ex.Message,
                IsAuthFailure = true,
            };
        } catch (Exception ex) {
            return new ConnectResult { Ok = false, Error = ex.Message };
        }
    }

    public async Task<RunResult> RunCaptureAsync(
            Connection c, string script, CancellationToken ct = default) {
        script = NormalizeLineEndings(script);
        var (client, _) = CreateClient(c);
        using (client) {
            await Task.Run(() => client.Connect(), ct).ConfigureAwait(false);
            try {
                using var cmd = client.CreateCommand(script);
                var stdout = await Task.Run(() => cmd.Execute(), ct)
                                       .ConfigureAwait(false);
                return new RunResult {
                    ExitStatus = cmd.ExitStatus ?? -1,
                    Stdout = stdout,
                    Stderr = cmd.Error,
                };
            } finally {
                client.Disconnect();
            }
        }
    }

    // Streams stdout + stderr line-by-line to the supplied callback. Returns
    // the final exit status once the command completes.
    public async Task<int> RunStreamAsync(
            Connection c,
            string script,
            Action<string> onLine,
            CancellationToken ct = default) {
        script = NormalizeLineEndings(script);
        var (client, _) = CreateClient(c);
        using (client) {
            await Task.Run(() => client.Connect(), ct).ConfigureAwait(false);
            try {
                using var cmd = client.CreateCommand(script);
                var handle = cmd.BeginExecute();
                using var outReader = new StreamReader(
                    cmd.OutputStream, Encoding.UTF8);
                using var errReader = new StreamReader(
                    cmd.ExtendedOutputStream, Encoding.UTF8);

                while (!handle.IsCompleted) {
                    ct.ThrowIfCancellationRequested();
                    var drained = DrainOnce(outReader, onLine)
                                | DrainOnce(errReader, onLine);
                    if (!drained) {
                        await Task.Delay(50, ct).ConfigureAwait(false);
                    }
                }
                while (DrainOnce(outReader, onLine)) { }
                while (DrainOnce(errReader, onLine)) { }
                cmd.EndExecute(handle);
                return cmd.ExitStatus ?? -1;
            } finally {
                client.Disconnect();
            }
        }
    }

    private static bool DrainOnce(StreamReader reader, Action<string> onLine) {
        if (reader.Peek() < 0) return false;
        var line = reader.ReadLine();
        if (line == null) return false;
        onLine(line);
        return true;
    }

    private sealed class FingerprintHolder {
        public string Value = "";
    }

    // Bash on the router treats \r as a literal char and barfs on every
    // line ("$'\r': command not found").  Source files checked out on
    // Windows have CRLF endings, which C# raw string literals preserve
    // verbatim — so any script we send needs LF normalisation before
    // landing on the wire.  Defensive: also handle bare \r.
    private static string NormalizeLineEndings(string s) {
        if (string.IsNullOrEmpty(s)) return s;
        return s.Replace("\r\n", "\n").Replace("\r", "\n");
    }

    private static (SshClient, FingerprintHolder) CreateClient(Connection c) {
        ConnectionInfo info;
        if (c.AuthMethod == AuthMethod.Password) {
            // UDM / UniFi OS sshd is typically configured with
            // PasswordAuthentication=no + KbdInteractiveAuthentication=yes,
            // which rejects SSH.NET's PasswordAuthenticationMethod (it only
            // implements the legacy "password" SSH method).  Register both
            // here so the client succeeds against either policy: the server
            // advertises one or the other, and SSH.NET tries the matching
            // one.
            var password = c.Password ?? "";
            var passwordAuth = new PasswordAuthenticationMethod(
                c.Username, password);
            var keyboardAuth = new KeyboardInteractiveAuthenticationMethod(
                c.Username);
            keyboardAuth.AuthenticationPrompt += (_, e) => {
                foreach (var prompt in e.Prompts) {
                    prompt.Response = password;
                }
            };
            info = new ConnectionInfo(
                c.Host, c.Port, c.Username,
                passwordAuth, keyboardAuth);
        } else {
            var keyFile = string.IsNullOrEmpty(c.PrivateKeyPassphrase)
                ? new PrivateKeyFile(c.PrivateKeyPath ?? "")
                : new PrivateKeyFile(c.PrivateKeyPath ?? "",
                                     c.PrivateKeyPassphrase);
            info = new ConnectionInfo(
                c.Host, c.Port, c.Username,
                new PrivateKeyAuthenticationMethod(c.Username, keyFile));
        }
        info.Timeout = TimeSpan.FromSeconds(15);

        var expected = c.HostFingerprint;
        var holder = new FingerprintHolder();
        var client = new SshClient(info);
        client.HostKeyReceived += (_, e) => {
            holder.Value = FormatFingerprint(e.HostKey);
            if (!string.IsNullOrEmpty(expected)
                && holder.Value != expected) {
                e.CanTrust = false;
                return;
            }
            e.CanTrust = true;
        };
        return (client, holder);
    }

    private static string FormatFingerprint(byte[] hostKey) {
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(hostKey);
        return "SHA256:" + Convert.ToBase64String(hash).TrimEnd('=');
    }
}
