cask "agent-keychain" do
  version "0.3.0"
  # Update this digest from akc-aarch64-apple-darwin.tar.gz.sha256 in the
  # corresponding GitHub release whenever version changes.
  sha256 "c19c2ec3167e4a727a4c3da46333a9e220a65137ad29d2bbcb06395d3a38a01e"

  url "https://github.com/Goooooooooody/agent-keychain/releases/download/v#{version}/akc-aarch64-apple-darwin.tar.gz"
  name "Agent Keychain"
  desc "Local encrypted keychain for user-approved agent secret access"
  homepage "https://github.com/Goooooooooody/agent-keychain"

  depends_on arch: :arm64

  binary "akc"
  binary "akc-tray"
end
