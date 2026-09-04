class Starforge < Formula
  desc "A developer productivity CLI for Stellar and Soroban workflows"
  homepage "https://github.com/StarsForges/StarForge"
  version "0.1.0"
  
  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/StarsForges/StarForge/releases/download/v0.1.0/starforge-darwin-x86_64.tar.gz"
    sha256 "REPLACE_WITH_DARWIN_X86_64_SHA256"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/StarsForges/StarForge/releases/download/v0.1.0/starforge-darwin-aarch64.tar.gz"
    sha256 "REPLACE_WITH_DARWIN_AARCH64_SHA256"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/StarsForges/StarForge/releases/download/v0.1.0/starforge-linux-x86_64.tar.gz"
    sha256 "REPLACE_WITH_LINUX_X86_64_SHA256"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/StarsForges/StarForge/releases/download/v0.1.0/starforge-linux-aarch64.tar.gz"
    sha256 "REPLACE_WITH_LINUX_AARCH64_SHA256"
  end

  def install
    bin.install "starforge"
  end

  test do
    system "#{bin}/starforge", "--version"
  end
end
