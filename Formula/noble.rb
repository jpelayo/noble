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

      # Interactive CIDR prompt (skipped in non-TTY environments like CI).
      if $stdin.tty?
        puts
        puts "  Remote access — allow connections to the Dashboard GUI and JSON-RPC API."
        puts "  Enter IP addresses or CIDR blocks (comma-separated)."
        puts "  Press Enter for localhost-only access."
        puts
        print "  Allowed IPs (e.g. 10.0.0.0/8): "
        input = $stdin.gets.chomp.strip
        unless input.empty?
          cidrs = input.split(",").map { |s| "\"#{s.strip}\"" }.join(", ")
          config.gsub!('allowed_ips = []', "allowed_ips = [#{cidrs}]")
          puts
          puts "  Remote access enabled. After starting, the dashboard will be at:"
          puts "  http://<this-host>:8785"
        end
      end

      (etc/"noble/noble.toml").write(config)
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

        brew services start noble       # starts in setup mode
        open http://<server-ip>:8785    # complete wizard in browser

      Open this port to internet: 8780 (or at least one of these 8780, 8781, 8782)

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
