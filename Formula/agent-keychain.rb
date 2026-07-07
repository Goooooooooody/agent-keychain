class AgentKeychain < Formula
  desc "Local encrypted keychain for user-approved agent secret access"
  homepage "https://github.com/Goooooooooody/agent-keychain"
  url "https://github.com/Goooooooooody/agent-keychain/archive/refs/tags/v0.1.1.tar.gz"
  sha256 "f81f4b6815b7f418fcf3da9852b71e2263def26433229f77067e8092ad34c32d"
  license "MIT"

  def install
    odie "agent-keychain currently ships a prebuilt binary for Apple Silicon macOS only" unless OS.mac? && Hardware::CPU.arm?

    bin.install "dist/aarch64-apple-darwin/akc"
  end

  def caveats
    <<~EOS
      Homebrew links `akc` into its prefix bin directory automatically.

      If your shell cannot find `akc`, add Homebrew to your PATH:
        echo 'eval "$(brew shellenv)"' >> ~/.zprofile
        eval "$(brew shellenv)"
    EOS
  end

  test do
    assert_match "akc 0.1.1", shell_output("#{bin}/akc --version")
    assert_match "agent request auto-approval: disabled", shell_output("#{bin}/akc config auto-approve status")
  end
end
