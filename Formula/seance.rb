class Seance < Formula
  desc "Ephemeral encrypted P2P chat CLI tool"
  homepage "https://github.com/no-way-labs/cauldron"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/no-way-labs/cauldron/releases/download/seance-v0.1.0/seance-macos-aarch64.tar.gz"
      sha256 "ef1f2c7cf5477f391af010217bdb6abcf6c8595fa244d9b476cde7bb8a3d67fe"
    else
      url "https://github.com/no-way-labs/cauldron/releases/download/seance-v0.1.0/seance-macos-x86_64.tar.gz"
      sha256 "afd04840357f10231ed905ec3f6613912e8572ace20cd85f9a484dbc796c8c41"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/no-way-labs/cauldron/releases/download/seance-v0.1.0/seance-linux-aarch64.tar.gz"
      sha256 "aa372db2181b873c6393d58dc3de7128d51a4dcdec0273c73e48d847b30048b2"
    else
      url "https://github.com/no-way-labs/cauldron/releases/download/seance-v0.1.0/seance-linux-x86_64.tar.gz"
      sha256 "75ee361f048c37f19a561dff8e0ab549dbe9108f2c7588d04fdb3e25bd8f79e7"
    end
  end

  def install
    bin.install "seance"
  end

  test do
    assert_match "seance", shell_output("#{bin}/seance 2>&1")
  end
end
