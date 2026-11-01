#!/bin/sh
set -eu
umask 077

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destdir=${1:-}
case "$destdir" in
  ""|/*) ;;
  *) printf 'DESTDIR must be an absolute staging path.\n' >&2; exit 1 ;;
esac
install_dir="$destdir/etc/proxy-firewall"
unit_dir="$destdir/etc/systemd/system"

for source in bin/proxy-firewall .env.example .creds.example proxy-firewall.example.conf proxy-firewall.service LICENSE; do
  test -f "$project_dir/$source" || { printf 'Missing installation source: %s\n' "$source" >&2; exit 1; }
done

# Online logical CPUs include hardware threads. Count on the installation host.
cpu_threads=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || nproc)
case "$cpu_threads" in
  ""|*[!0-9]*|0) printf 'Cannot determine a positive online CPU count.\n' >&2; exit 1 ;;
esac
gomaxprocs=$((cpu_threads * 2 / 5))
if [ "$gomaxprocs" -lt 1 ]; then gomaxprocs=1; fi

# mkdir -p leaves existing directories, their permissions and their contents alone.
mkdir -p "$install_dir/bin" "$install_dir/log" "$install_dir/files" \
  "$install_dir/.cache" "$install_dir/.certs" "$unit_dir"

copy_if_missing() {
  if [ ! -e "$2" ] && [ ! -L "$2" ]; then
    # Noclobber also prevents a concurrent install from overwriting a new file.
    (set -C; cat "$1" > "$2")
  fi
}

copy_if_missing "$project_dir/.env.example" "$install_dir/.env"
copy_if_missing "$project_dir/.creds.example" "$install_dir/.creds"
copy_if_missing "$project_dir/LICENSE" "$install_dir/LICENSE"
copy_if_missing "$project_dir/proxy-firewall.example.conf" "$install_dir/proxy-firewall.conf"
copy_if_missing /dev/null "$install_dir/log/proxy-firewall.log"

if [ -d "$install_dir/bin/proxy-firewall" ]; then
  printf 'Cannot replace bin/proxy-firewall: destination is a directory.\n' >&2
  exit 1
fi

# Replace the executable atomically, including when an older process is running.
binary_tmp=$(mktemp "$install_dir/bin/.proxy-firewall.XXXXXX")
trap 'rm -f "$binary_tmp"' EXIT
trap 'exit 1' HUP INT TERM
install -m 0755 "$project_dir/bin/proxy-firewall" "$binary_tmp"
mv -f "$binary_tmp" "$install_dir/bin/proxy-firewall"
# Pass the calculated Go runtime limit without modifying either configuration file.
unit_tmp=$(mktemp "$unit_dir/.proxy-firewall.service.XXXXXX")
trap 'rm -f "$binary_tmp" "$unit_tmp"' EXIT
sed "s/GOMAXPROCS=1 /GOMAXPROCS=$gomaxprocs /" "$project_dir/proxy-firewall.service" > "$unit_tmp"
chmod 0644 "$unit_tmp"
mv -f "$unit_tmp" "$unit_dir/proxy-firewall.service"

printf 'Installed binary and systemd unit; existing configuration and data preserved.\n'
printf 'Online CPU threads: %s; GOMAXPROCS: %s.\n' "$cpu_threads" "$gomaxprocs"
printf 'Service output appends to /etc/proxy-firewall/log/proxy-firewall.log.\n'
if [ -z "$destdir" ]; then
  printf 'Run systemctl daemon-reload, then start or restart proxy-firewall when ready.\n'
fi
