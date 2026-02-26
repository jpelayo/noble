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

  on_linux do
    depends_on "llvm" => :build     # bindgen (librocksdb-sys) needs libclang via llvm
  end

  def install
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
    # Create runtime directories.
    (var/"noble/data").mkpath
    (var/"noble/keystore").mkpath
    (var/"noble/logs").mkpath

    # Copy sample config if no config exists yet.
    unless (etc/"noble/noble.toml").exist?
      cp etc/"noble/noble.toml.sample", etc/"noble/noble.toml"
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
      NOBLE blockchain node installed successfully.

      Configuration:  #{etc}/noble/noble.toml
      Data directory: #{var}/noble/data
      Keystore:       #{var}/noble/keystore
      Logs:           #{var}/log/noble-node.log
      GUI files:      #{prefix}/noble-gui/

      Port summary:
        8780  P2P (libp2p TCP + Noise + Yamux)
        8783  JSON-RPC HTTP
        8784  WebSocket subscriptions
        8785  Dashboard GUI
        8786  Prometheus /metrics (disabled by default)

      Quick start:
        # Edit configuration
        $EDITOR #{etc}/noble/noble.toml

        # Run interactively
        noble-node run #{etc}/noble/noble.toml

        # Or run as a background service
        brew services start noble

        # Check status
        noble-node status

        # Stop background service
        brew services stop noble

      Tools:
        noble-tool genesis --output genesis.cbor
        noble-tool benchmark --suite all
        noble-tool validate-chain --data-dir #{var}/noble/data
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
