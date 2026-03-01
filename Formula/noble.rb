# Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
# SPDX-License-Identifier: Apache-2.0
#
# Homebrew formula for the NOBLE blockchain node.
#
# Installs three binaries (noble-node, noble-tool, noble-faucet), the dashboard
# GUI static files, shell completions, a sample configuration, and a background
# service definition (launchd on macOS, systemd on Linux).
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
  #   brew install --HEAD noble --localonly  # force localhost only (default)
  # Alternatively: NOBLE_ALLOWED_IPS=192.168.0.0/16 brew install ...

  option "with-192", "Allow remote access from 192.168.0.0/16 (home LAN)"
  option "with-10",  "Allow remote access from 10.0.0.0/8 (corporate LAN)"
  option "with-172", "Allow remote access from 172.16.0.0/12 (Docker/private)"
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
    (prefix/"noble-gui").install Dir["noble-gui/*"]

    # Shell completions (bash, zsh, fish).
    generate_completions_from_executable(bin/"noble-node", "completions")

    # Sample configuration file.
    (etc/"noble").mkpath
    (etc/"noble").install "noble.toml" => "noble.toml.sample"
  end

  def post_install
    (var/"noble/data").mkpath
    (var/"noble/keystore").mkpath
    (var/"noble/logs").mkpath

    unless (etc/"noble/noble.toml").exist?
      config = (etc/"noble/noble.toml.sample").read

      # Inject absolute Homebrew paths (replace relative defaults).
      config.gsub!('data_dir = "data"', "data_dir = \"#{var}/noble/data\"")
      config.gsub!('keystore_path = "keystore"', "keystore_path = \"#{var}/noble/keystore\"")

      # Remote access — CLI flags (--allow192 etc.) or NOBLE_ALLOWED_IPS env var.
      # Never prompts interactively. Default: localhost-only.
      cidrs = []
      cidrs << "192.168.0.0/16" if build.with?("192")
      cidrs << "10.0.0.0/8"     if build.with?("10")
      cidrs << "172.16.0.0/12"  if build.with?("172")

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

      unless cidrs.empty?
        cidr_str = cidrs.map { |s| "\"#{s}\"" }.join(", ")
        config.gsub!('allowed_ips = []', "allowed_ips = [#{cidr_str}]")
        puts
        puts "  Remote access enabled for: #{cidrs.join(", ")}"
        puts "  After starting, the dashboard will be at: https://<this-host>:8785"
      else
        puts
        puts "  Localhost-only mode: Dashboard and RPC are accessible on this machine only."
        puts "  To allow remote access later, edit: #{etc}/noble/noble.toml"
        puts "    allowed_ips = [\"192.168.0.0/16\"]"
      end

      (etc/"noble/noble.toml").write(config)
    end

    # Warn if Noble ports are already occupied (avoids confusion with mock servers, etc.)
    blocked = []
    {8780 => "P2P", 8783 => "RPC/WebSocket", 8785 => "Dashboard GUI"}.each do |port, label|
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

        brew install --HEAD noble --with-192  # home LAN  (192.168.0.0/16)
        brew install --HEAD noble --with-10   # corporate (10.0.0.0/8)
        brew install --HEAD noble --with-172  # Docker    (172.16.0.0/12)

      Ports that should be reachable:

        8780  P2P (open to internet for full connectivity)
        8783  JSON-RPC + WebSocket (HTTPS/WSS) — open for client/wallet access

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

    # Verify config validation against the sample config.
    system bin/"noble-node", "config", "validate", etc/"noble/noble.toml.sample"

    # Verify GUI static files are installed.
    assert_predicate prefix/"noble-gui/index.html", :exist?
  end
end
