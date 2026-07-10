cask "agent-keychain" do
  version "0.2.0"
  # Update this digest from akc-aarch64-apple-darwin.tar.gz.sha256 in the
  # corresponding GitHub release whenever version changes.
  sha256 "49867d7b7e778ab85658ccd50b8705503c7b3e932f33515dfe134b5ee531380b"

  url "https://github.com/Goooooooooody/agent-keychain/releases/download/v#{version}/akc-aarch64-apple-darwin.tar.gz"
  name "Agent Keychain"
  desc "Local encrypted keychain for user-approved agent secret access"
  homepage "https://github.com/Goooooooooody/agent-keychain"

  depends_on arch: :arm64

  binary "akc"
end
