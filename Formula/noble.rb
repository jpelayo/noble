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
  desc "NOBLE blockchain node — Proof of Reputation consensus protocol"
  homepage "https://github.com/jpelayo/noble"
  license "Apache-2.0"
  head "https://github.com/jpelayo/noble.git", branch: "main"

  # Remote access flags (set at install time, applied to noble.toml):
  #   brew install --HEAD noble --with-192   # allow 192.168.0.0/16
  #   brew install --HEAD noble --with-10    # allow 10.0.0.0/8
  #   brew install --HEAD noble --with-172   # allow 172.16.0.0/12
  #   brew install --HEAD noble --with-100   # allow 100.64.0.0/10 (Tailscale)
  #   brew install --HEAD noble --localonly  # force localhost only (default)
  # Alternatively: NOBLE_ALLOWED_IPS=192.168.0.0/16 brew install ...

  option "with-192", "Allow remote access from 192.168.0.0/16 (home LAN)"
  option "with-10",  "Allow remote access from 10.0.0.0/8 (corporate LAN)"
  option "with-172", "Allow remote access from 172.16.0.0/12 (Docker/private)"
  option "with-100", "Allow remote access from 100.64.0.0/10 (Tailscale)"
  option "localonly", "Force localhost-only mode (default)"

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

    # Build all three binaries in release mode.
    system "cargo", "build", "--release",
           "--bin", "noble-node",
           "--bin", "noble-tool",
           "--bin", "noble-faucet"

    bin.install "target/release/noble-node"
    bin.install "target/release/noble-tool"
    bin.install "target/release/noble-faucet"

    # Dashboard GUI static files.
    # gui_server.rs detect_gui_dir() searches <binary_dir>/../noble-gui/ first,
    # which resolves through the Homebrew symlink to the Cellar prefix.
    # Remove stale GUI dir from previous installs so files are always fresh.
    rm_rf prefix/"noble-gui"
    (prefix/"noble-gui").install Dir["noble-gui/*"]

    # Shell completions (bash, zsh, fish) — remove stale files first.
    rm_f bash_completion/"noble-node"
    rm_f zsh_completion/"_noble-node"
    rm_f fish_completion/"noble-node.fish"
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

    # Env var fallback (for CI / scripted installs).
    if cidrs.empty? && !build.include?("localonly")
      allowed = ENV["NOBLE_ALLOWED_IPS"].to_s.strip
      if !allowed.empty? && allowed != "localonly"
        require "ipaddr"
        entries = allowed.split(",").map(&:strip).reject(&:empty?)
        bad = entries.reject { |e| IPAddr.new(e) rescue false }
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
      TOML

      if cidrs.any?
        puts
        puts "  Remote access enabled for: #{cidrs.join(", ")}"
        puts "  After starting, the dashboard will be at: https://<this-host>:8785"
      else
        puts
        puts "  Localhost-only mode: Dashboard and RPC are accessible on this machine only."
        puts "  To allow remote access later, edit: #{etc}/noble/noble.toml"
        puts "    allowed_ips = [\"192.168.0.0/16\"]"
      end
    end

    # Warn if Noble ports are already occupied (avoids confusion with mock servers, etc.)
    blocked = []
    {8780 => "P2P", 8783 => "JSON-RPC HTTP", 8784 => "WebSocket", 8785 => "Dashboard GUI"}.each do |port, label|
      pid = `lsof -ti :#{port} 2>/dev/null`.strip
      unless pid.empty?
        proc_name = `ps -o comm= -p #{pid} 2>/dev/null`.strip
        blocked << {port: port, label: label, pid: pid, proc: proc_name}
      end
    end
    unless blocked.empty?
      puts
      puts "  " + "!" * 60
      puts "  !!  BLOCKED PORTS — Noble cannot start until freed  !!"
      puts "  " + "!" * 60
      blocked.each do |b|
        puts "  !!  Port #{b[:port]} (#{b[:label]}): PID #{b[:pid]} (#{b[:proc]})"
      end
      puts "  !!"
      puts "  !!  Fix:  #{blocked.map { |b| "kill #{b[:pid]}" }.join(" && ")}"
      puts "  " + "!" * 60
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
    log_path var/"log/noble-node.log"
    error_log_path var/"log/noble-node.log"
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

        8780  P2P (open to internet for full connectivity)
        8783  JSON-RPC HTTP-only (HTTPS) — open for client/wallet access

      Paths:
        Config:    #{etc}/noble/noble.toml
        Data:      #{var}/noble/data
        Keystore:  #{var}/noble/keystore
        Logs:      #{var}/log/noble-node.log
        GUI:       #{prefix}/noble-gui/
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
    assert_predicate testpath/"test-genesis.cbor", :exist?
    assert (testpath/"test-genesis.cbor").size.positive?

    # Verify GUI static files are installed.
    assert_predicate prefix/"noble-gui/index.html", :exist?
  end
end
