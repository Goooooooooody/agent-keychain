cask "agent-keychain" do
  version "0.1.2"
  # Update this digest from akc-aarch64-apple-darwin.tar.gz.sha256 in the
  # corresponding GitHub release whenever version changes.
  sha256 "adcfc32d4927b21706e149f1ca332ad3f5fa0b230299c2de03166631077ff226"

  url "https://github.com/Goooooooooody/agent-keychain/releases/download/v#{version}/akc-aarch64-apple-darwin.tar.gz"
  name "Agent Keychain"
  desc "Local encrypted keychain for user-approved agent secret access"
  homepage "https://github.com/Goooooooooody/agent-keychain"

  depends_on arch: :arm64

  binary "akc"
end
