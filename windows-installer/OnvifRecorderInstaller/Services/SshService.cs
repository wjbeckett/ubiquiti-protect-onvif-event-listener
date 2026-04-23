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
        } catch (Exception ex) {
            return new ConnectResult { Ok = false, Error = ex.Message };
        }
    }

    public async Task<RunResult> RunCaptureAsync(
            Connection c, string script, CancellationToken ct = default) {
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

    private static (SshClient, FingerprintHolder) CreateClient(Connection c) {
        ConnectionInfo info;
        if (c.AuthMethod == AuthMethod.Password) {
            info = new ConnectionInfo(
                c.Host, c.Port, c.Username,
                new PasswordAuthenticationMethod(
                    c.Username, c.Password ?? ""));
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
