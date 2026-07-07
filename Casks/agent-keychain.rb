cask "agent-keychain" do
  version "0.1.1"
  sha256 "f81f4b6815b7f418fcf3da9852b71e2263def26433229f77067e8092ad34c32d"

  url "https://github.com/Goooooooooody/agent-keychain/archive/refs/tags/v#{version}.tar.gz"
  name "Agent Keychain"
  desc "Local encrypted keychain for user-approved agent secret access"
  homepage "https://github.com/Goooooooooody/agent-keychain"

  binary "agent-keychain-#{version}/dist/aarch64-apple-darwin/akc", target: "akc"
end
