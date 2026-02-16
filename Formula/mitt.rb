class Mitt < Formula
  desc "Encrypted file transfer CLI tool"
  homepage "https://github.com/no-way-labs/cauldron"
  version "0.4.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/no-way-labs/cauldron/releases/download/v0.4.1/mitt-macos-aarch64.tar.gz"
      sha256 "27522ae798b98eaf4c1d3660b9b00c7f3cc72888695aa97e78eb56183728f4d0"
    else
      url "https://github.com/no-way-labs/cauldron/releases/download/v0.4.1/mitt-macos-x86_64.tar.gz"
      sha256 "7f6f6d810d02f5eb362d9d52ad3d6fc4ab2e1b024a6667cd048f32b15ca9e312"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/no-way-labs/cauldron/releases/download/v0.4.1/mitt-linux-aarch64.tar.gz"
      sha256 "e828f4eff89960401876e96e0e6562f257dcff8f31635dcf168fe989d2ffaf05"
    else
      url "https://github.com/no-way-labs/cauldron/releases/download/v0.4.1/mitt-linux-x86_64.tar.gz"
      sha256 "b77b736d6ebf24247d25a940d0071eb3fba8a0a6514c4db21efea8ecd3098580"
    end
  end

  def install
    bin.install "mitt"
  end

  test do
    assert_match "mitt", shell_output("#{bin}/mitt --help 2>&1", 1)
  end
end
