class Seance < Formula
  desc "Ephemeral encrypted P2P chat CLI tool"
  homepage "https://github.com/no-way-labs/cauldron"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/no-way-labs/cauldron/releases/download/seance-v0.1.0/seance-macos-aarch64.tar.gz"
      sha256 "PLACEHOLDER"
    else
      url "https://github.com/no-way-labs/cauldron/releases/download/seance-v0.1.0/seance-macos-x86_64.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/no-way-labs/cauldron/releases/download/seance-v0.1.0/seance-linux-aarch64.tar.gz"
      sha256 "PLACEHOLDER"
    else
      url "https://github.com/no-way-labs/cauldron/releases/download/seance-v0.1.0/seance-linux-x86_64.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  def install
    bin.install "seance"
  end

  test do
    assert_match "seance", shell_output("#{bin}/seance 2>&1")
  end
end
