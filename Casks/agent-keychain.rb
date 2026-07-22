cask "agent-keychain" do
  version "0.4.0"
  # Update this digest from akc-aarch64-apple-darwin.tar.gz.sha256 in the
  # corresponding GitHub release whenever version changes.
  sha256 "637ed946b2860c8785dff6a3fd5577aaddb1b551575d3c80a83cc1633bd8a61d"

  url "https://github.com/Goooooooooody/agent-keychain/releases/download/v#{version}/akc-aarch64-apple-darwin.tar.gz"
  name "Agent Keychain"
  desc "Local encrypted keychain for user-approved agent secret access"
  homepage "https://github.com/Goooooooooody/agent-keychain"

  depends_on arch: :arm64

  binary "akc"
  binary "akc-tray"
end
