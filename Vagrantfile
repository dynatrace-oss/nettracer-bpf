$script = <<-SCRIPT
    apt update -y && \
    apt install -y \
    wget lsb-release gpg software-properties-common \
    git libelf-dev libboost-program-options-dev \
    make gcc-8 g++-8 linux-headers-5.4.0-42-generic cmake && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 700 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 800 --slave /usr/bin/g++ g++ /usr/bin/g++-8 && \
    update-alternatives --install /usr/bin/cc cc /usr/bin/gcc 100 --slave /usr/bin/c++ c++ /usr/bin/g++
    wget -O - https://apt.llvm.org/llvm.sh | bash -s - 10
    git clone --depth 1 --branch 7.0.3 https://github.com/fmtlib/fmt.git && \
    cd fmt && mkdir build && cd build && \
    cmake -DFMT_TEST=OFF .. && make -j && make install
    git clone --depth 1 --branch v1.8.1 https://github.com/gabime/spdlog.git && \
    cd spdlog && mkdir build && cd build && \
    cmake -DSPDLOG_BUILD_EXAMPLE=OFF -DSPDLOG_FMT_EXTERNAL=ON .. && make -j && make install
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box =  "ubuntu/bionic64"
  config.vm.provider "virtualbox" do |pmv|
      pmv.memory = 4096
  end
  config.disksize.size = '20GB'
  config.vm.provision "shell", inline: $script
end
