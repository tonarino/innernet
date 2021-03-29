#!/usr/bin/env bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"

info() {
  TERM=${TERM:-dumb} echo -e "$(tput setaf 4)- $@$(tput sgr0)" 1>&2
}

cmd() {
  echo "[#] $*" >&2
  "$@"
}

set -e

info "building innernet binary."
cmd cargo build --release --bin innernet

info "installing innernet binary."
cmd sudo cp -f $ROOT_DIR/target/release/innernet /usr/local/bin
cmd sudo ln -s /usr/local/bin/innernet /usr/local/bin/inn

if ! which wg > /dev/null; then
  info "installing wireguard."
  cmd brew install wireguard-tools
fi

info "installing launch daemon for innernet daemon script."
echo "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>no.tonari.innernet</string>
    <key>ProgramArguments</key>
    <array>
      <string>/usr/local/bin/innernet</string>
      <string>fetch</string>
      <string>--daemon</string>
      <string>--interval</string>
      <string>60</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>LaunchOnlyOnce</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/innernet.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/innernet.log</string>
    <key>EnvironmentVariables</key>
    <dict>
      <key>PATH</key>
      <string>/usr/local/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
" | cmd sudo tee /Library/LaunchDaemons/no.tonari.innernet.plist
cmd sudo launchctl enable system/no.tonari.innernet
cmd sudo launchctl bootstrap system /Library/LaunchDaemons/no.tonari.innernet.plist

