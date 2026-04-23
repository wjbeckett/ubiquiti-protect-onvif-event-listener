using System;
using System.Collections.Generic;

namespace OnvifRecorderInstaller.Services;

public static class InstallScripts {
    public const string RepoUrl =
        "https://danielwoz.github.io/ubiquiti-protect-onvif-event-listener";
    public const string Keyring =
        "/usr/share/keyrings/onvif-recorder-archive-keyring.gpg";
    public const string SourcesFile =
        "/etc/apt/sources.list.d/onvif-recorder.list";
    public const string ChannelFile = "/etc/onvif-recorder/channel";
    public const string RunnablesYaml = "/data/unifi-core/config/runnables.yaml";

    public static readonly IReadOnlyList<string> ValidChannels =
        new[] { "stable", "rc", "early-access" };

    public static string BuildInstallScript(string channel) {
        ValidateChannel(channel);
        return $$"""
            set -e
            export DEBIAN_FRONTEND=noninteractive

            mkdir -p /usr/share/keyrings
            curl -fsSL {{RepoUrl}}/onvif-recorder.gpg -o /tmp/onvif-recorder.gpg
            gpg --dearmor < /tmp/onvif-recorder.gpg > {{Keyring}}
            chmod 0644 {{Keyring}}
            rm -f /tmp/onvif-recorder.gpg

            mkdir -p /etc/onvif-recorder
            echo "{{channel}}" > {{ChannelFile}}

            echo "deb [arch=arm64 signed-by={{Keyring}}] {{RepoUrl}} {{channel}} main" \
              > {{SourcesFile}}

            apt-get update \
              -o Dir::Etc::sourcelist={{SourcesFile}} \
              -o Dir::Etc::sourceparts=- \
              -o APT::Get::List-Cleanup=0

            apt-get install -y onvif-recorder

            dpkg-query -W -f='${Version}' onvif-recorder
            """;
    }

    public static string BuildUpgradeScript() {
        return $$"""
            set -e
            export DEBIAN_FRONTEND=noninteractive

            apt-get update \
              -o Dir::Etc::sourcelist={{SourcesFile}} \
              -o Dir::Etc::sourceparts=- \
              -o APT::Get::List-Cleanup=0

            apt-get install -y --only-upgrade onvif-recorder

            dpkg-query -W -f='${Version}' onvif-recorder
            """;
    }

    public static string BuildUninstallScript() {
        return $"""
            set -e
            export DEBIAN_FRONTEND=noninteractive

            apt-get purge -y onvif-recorder || true
            rm -f {SourcesFile}
            rm -f {Keyring}
            echo "done"
            """;
    }

    // Prints the Protect channel (stable | rc | early-access) or empty if
    // unknown. Mirrors debian/detect-channel.sh.
    public static string BuildDetectChannelScript() {
        return $$"""
            set -e
            RUNNABLES={{RunnablesYaml}}
            if [ ! -f "$RUNNABLES" ]; then
                echo ""
                exit 0
            fi
            RAW=$(awk '
                /^releaseChannels:/ { in_block=1; next }
                in_block && /^[^[:space:]]/ { in_block=0 }
                in_block && /^[[:space:]]+protect[[:space:]]*:/ {
                    sub(/^[^:]*:[[:space:]]*/, "")
                    gsub(/["'"'"']/, "")
                    sub(/[[:space:]]*#.*$/, "")
                    print; exit
                }
            ' "$RUNNABLES" 2>/dev/null | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
            case "$RAW" in
                release)           echo "stable" ;;
                release-candidate) echo "rc" ;;
                beta|early-access) echo "early-access" ;;
                *)                 echo "" ;;
            esac
            """;
    }

    public static string BuildVersionScript() {
        return "dpkg-query -W -f='${Version}' onvif-recorder 2>/dev/null || echo ''";
    }

    public static void ValidateChannel(string channel) {
        foreach (var v in ValidChannels) {
            if (v == channel) return;
        }
        throw new ArgumentException(
            $"invalid channel '{channel}' (expected stable|rc|early-access)");
    }
}
