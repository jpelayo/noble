# Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
# SPDX-License-Identifier: Apache-2.0
#
# Homebrew formula for the NOBLE blockchain node.
#
# Installs three binaries (noble-node, noble-tool, noble-faucet), the dashboard
# GUI static files, shell completions, and a background service definition
# (launchd on macOS, systemd on Linux).
#
# Install from local checkout:
#   brew install --HEAD --formula Formula/noble.rb
#
# Install from remote:
#   brew tap jpelayo/noble https://github.com/jpelayo/noble.git
#   brew install --HEAD jpelayo/noble/noble

class Noble < Formula
  desc "Proof-of-Reputation blockchain node, tools, and dashboard"
  homepage "https://github.com/jpelayo/noble"
  license "Apache-2.0"
  head "https://github.com/jpelayo/noble.git", branch: "main"

  # Remote access flags (set at install time, applied to noble.toml):
  #   brew install --HEAD noble --with-192   # allow 192.168.0.0/16
  #   brew install --HEAD noble --with-10    # allow 10.0.0.0/8
  #   brew install --HEAD noble --with-172   # allow 172.16.0.0/12
  #   brew install --HEAD noble --with-100   # allow 100.64.0.0/10 (Tailscale)
  # Localhost-only is the default (no flag). Alternatively:
  #   NOBLE_ALLOWED_IPS=192.168.0.0/16 brew install ...   (use "localonly" to force localhost)

  option "with-192", "Allow remote access from 192.168.0.0/16 (home LAN)"
  option "with-10",  "Allow remote access from 10.0.0.0/8 (corporate LAN)"
  option "with-172", "Allow remote access from 172.16.0.0/12 (Docker/private)"
  option "with-100", "Allow remote access from 100.64.0.0/10 (Tailscale)"

  depends_on "cmake" => :build      # librocksdb-sys C++ compilation
  depends_on "pkg-config" => :build # system library detection on Linux
  depends_on "rust" => :build
  depends_on "openssl@3"            # openssl-sys crate

  on_linux do
    depends_on "llvm" => :build     # bindgen (librocksdb-sys) needs libclang via llvm
  end

  def install
    # openssl-sys needs the brew openssl prefix; pkg-config alone is unreliable on Linux.
    ENV["OPENSSL_DIR"] = Formula["openssl@3"].opt_prefix
    # Share one target dir across the three installs so workspace dependencies
    # compile once, not three times (the bins live in separate workspace crates,
    # so each needs its own `cargo install`).
    ENV["CARGO_TARGET_DIR"] = buildpath/"target"

    system "cargo", "install", *std_cargo_args(path: "noble-node")
    system "cargo", "install", *std_cargo_args(path: "noble-tool")
    system "cargo", "install", *std_cargo_args(path: "noble-faucet")

    # Dashboard GUI static files.
    # gui_server.rs detect_gui_dir() searches <binary_dir>/../noble-gui/ first,
    # which resolves through the Homebrew symlink to the Cellar prefix.
    # Remove stale GUI dir from a same-revision reinstall so files are fresh.
    rm_r prefix/"noble-gui" if (prefix/"noble-gui").exist?
    (prefix/"noble-gui").install Dir["noble-gui/*"]

    # Shell completions (bash, zsh, fish) — clear any stale files first.
    [bash_completion/"noble-node", zsh_completion/"_noble-node",
     fish_completion/"noble-node.fish"].each { |f| rm f if f.exist? }
    generate_completions_from_executable(bin/"noble-node", "completions")

    # No sample config file needed — the node auto-generates noble.toml
    # on first boot when no config exists (headless bootstrap mode).
  end

  def post_install
    (var/"noble/data").mkpath
    (var/"noble/keystore").mkpath
    (var/"noble/logs").mkpath

    # Verify binary consistency — catches cross-compilation or
    # architecture-specific encoding bugs before the node starts.
    system bin/"noble-tool", "verify-wire"
    system bin/"noble-tool", "verify-codec"

    # Build noble.toml with brew-managed paths and optional remote access.
    # Remote access flags (--with-192 etc.) pre-configure allowed_ips so the
    # GUI setup wizard is reachable from the LAN on first boot.
    cidrs = []
    cidrs << "192.168.0.0/16" if build.with?("192")
    cidrs << "10.0.0.0/8"     if build.with?("10")
    cidrs << "172.16.0.0/12"  if build.with?("172")
    cidrs << "100.64.0.0/10"  if build.with?("100")

    # Env var fallback (for CI / scripted installs). Set NOBLE_ALLOWED_IPS to
    # "localonly" to force localhost even when other CIDRs would apply.
    if cidrs.empty?
      allowed = ENV["NOBLE_ALLOWED_IPS"].to_s.strip
      if !allowed.empty? && allowed != "localonly"
        require "ipaddr"
        entries = allowed.split(",").map(&:strip).reject(&:empty?)
        bad = entries.reject do |e|
          IPAddr.new(e)
          true
        rescue
          false
        end
        unless bad.empty?
          opoo "Invalid NOBLE_ALLOWED_IPS entries ignored: #{bad.join(", ")}"
          entries -= bad
        end
        cidrs = entries
      end
    end

    unless (etc/"noble/noble.toml").exist?
      # Always write noble.toml with brew-managed paths so the node stores
      # data under Homebrew's var/ prefix, not the user's home directory.
      (etc/"noble").mkpath
      cidr_toml = cidrs.any? ? cidrs.map { |s| "\"#{s}\"" }.join(", ") : ""
      allowed_line = cidrs.any? ? "allowed_ips = [#{cidr_toml}]" : "allowed_ips = []"

      (etc/"noble/noble.toml").write <<~TOML
        # NOBLE node configuration — generated by Homebrew
        # The node fills in missing sections with defaults on first boot.
        # Complete setup via the GUI wizard at https://127.0.0.1:8785

        [api]
        remote_setup = true
        #{allowed_line}

        [storage]
        data_dir = "#{var}/noble/data"

        [wallet]
        keystore_path = "#{var}/noble/keystore"

        # In-process size-based rotating logs (node-owned, hard-capped). The
        # node writes the real log here; launchd only captures pre-init stderr
        # to a separate tiny startup file (see the service block), so nothing
        # grows unbounded. Adjust max_size_bytes live from the GUI Settings.
        [logging]
        file_enabled = true
        file_path = "#{var}/log/noble-node.log"
        max_size_bytes = 1073741824

        # Disable stderr fan-out for the background service so launchd's capture
        # file stays tiny — the rotating file above is the canonical log.
        [trace]
        stderr_enabled = false
      TOML

      puts
      if cidrs.any?
        puts "  Remote access enabled for: #{cidrs.join(", ")}"
        puts "  After starting, the dashboard will be at: https://<this-host>:8785"
      else
        puts "  Localhost-only mode: Dashboard and RPC are accessible on this machine only."
        puts "  To allow remote access later, edit: #{etc}/noble/noble.toml"
        puts "    allowed_ips = [\"192.168.0.0/16\"]"
      end
    end

    # Warn if Noble ports are already occupied by a non-Noble process.
    blocked = []
    ports = {
      8780 => "P2P", 8783 => "JSON-RPC HTTP", 8784 => "WebSocket",
      8785 => "Dashboard GUI", 8786 => "Faucet"
    }
    ports.each do |port, label|
      pid = `lsof -ti :#{port} -sTCP:LISTEN 2>/dev/null`.strip
      next if pid.empty?

      proc_name = `ps -o comm= -p #{pid} 2>/dev/null`.strip
      next if proc_name.match?(/noble-node|noble-faucet/)

      blocked << { port: port, label: label, pid: pid, proc: proc_name }
    end
    unless blocked.empty?
      puts
      puts "  " + ("!" * 60)
      puts "  !!  WARNING — Ports may be in use                   !!"
      puts "  " + ("!" * 60)
      blocked.each do |b|
        puts "  !!  Port #{b[:port]} (#{b[:label]}): PID #{b[:pid]} (#{b[:proc]})"
      end
      puts "  !!"
      puts "  !!  Fix:  #{blocked.map { |b| "kill #{b[:pid]}" }.join(" && ")}"
      puts "  " + ("!" * 60)
      puts
    end
  end

  # Background service definition.
  # macOS: launchd plist via `brew services start noble`
  # Linux: systemd unit via `brew services start noble`
  service do
    run [opt_bin/"noble-node", "run", etc/"noble/noble.toml",
         "--pid-file", var/"noble/noble.pid"]
    working_dir var/"noble"
    # The node owns var/log/noble-node.log as a size-capped rotating log. launchd
    # only captures pre-tracing-init output (a few lines per boot) to a separate
    # startup file, so neither file grows unbounded.
    # NOTE for upgrades: an existing etc/noble/noble.toml is NOT regenerated — add
    # `[trace]\nstderr_enabled = false` to it so launchd's startup file stays tiny.
    log_path var/"log/noble-startup.log"
    error_log_path var/"log/noble-startup.log"
    keep_alive true
  end

  def caveats
    <<~EOS
      CLI setup:

        noble-node setup               # configure identity, wallet, TOTP
        brew services start noble       # start as background service

      GUI setup (headless):

        brew services start noble       # start the background service
        open https://<server-ip>:8785   # complete wizard in browser

      Remote access (set before install, or edit noble.toml later):

        brew install --HEAD noble --with-192  # home LAN   (192.168.0.0/16)
        brew install --HEAD noble --with-10   # corporate  (10.0.0.0/8)
        brew install --HEAD noble --with-172  # Docker     (172.16.0.0/12)
        brew install --HEAD noble --with-100  # Tailscale  (100.64.0.0/10)

      Ports that should be reachable:

        8780  P2P         ↔ inbound+outbound (open to internet for full connectivity)
        8783  JSON-RPC    ← inbound only (HTTPS — clients/wallets connect here)
        8786  Faucet      ← inbound only (HTTPS — clients request tokens here)

      Paths:
        Config:    #{etc}/noble/noble.toml
        Data:      #{var}/noble/data
        Keystore:  #{var}/noble/keystore
        Logs:      #{var}/log/noble-node.log  (rotating, size-capped)
                   #{var}/log/noble-startup.log  (launchd capture, boot only)
        GUI:       #{prefix}/noble-gui/

      The node logs to the path in [logging] file_path; if that key is absent
      the log lands in the data dir instead. The node prints its effective log
      path at startup — trust that line over this one.
    EOS
  end

  test do
    # Verify all three binaries produce version output.
    assert_match "noble-node", shell_output("#{bin}/noble-node --version")
    assert_match "noble-tool", shell_output("#{bin}/noble-tool --version")
    assert_match "noble-faucet", shell_output("#{bin}/noble-faucet --version")

    # Verify genesis block generation.
    system bin/"noble-tool", "genesis",
           "--network", "regtest",
           "--output", testpath/"test-genesis.cbor"
    assert_path_exists testpath/"test-genesis.cbor"
    assert (testpath/"test-genesis.cbor").size.positive?

    # Verify GUI static files are installed.
    assert_path_exists prefix/"noble-gui/index.html"
  end
end
