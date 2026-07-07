class AgentKeychain < Formula
  desc "Local encrypted keychain for user-approved agent secret access"
  homepage "https://github.com/Goooooooooody/agent-keychain"
  url "https://github.com/Goooooooooody/agent-keychain/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "9821fccd5f773790acbbd9795d98a38dd5df15475c123225cefb640ba73b590f"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "akc", shell_output("#{bin}/akc --version")
    assert_match "agent request auto-approval: disabled", shell_output("#{bin}/akc config auto-approve status")
  end
end
