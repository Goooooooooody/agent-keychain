cask "agent-keychain" do
  version "0.1.2"
  sha256 "e57230eca9ce907c2dc4fba57bdf27cb98c0dff5ce39b63cc88140b429ab5942"

  url "https://github.com/Goooooooooody/agent-keychain/archive/refs/tags/v#{version}.tar.gz"
  name "Agent Keychain"
  desc "Local encrypted keychain for user-approved agent secret access"
  homepage "https://github.com/Goooooooooody/agent-keychain"

  binary "agent-keychain-#{version}/dist/aarch64-apple-darwin/akc", target: "akc"
end
