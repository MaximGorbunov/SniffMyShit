#!/bin/bash

linux_images=("pcap-linux-armv5-musl" "pcap-linux-armv6-musl" "pcap-linux-armv7l-musl" "pcap-linux-armv8-musl" "pcap-linux-arm64" "pcap-linux-amd64")
linux_archs=("linux-armv5-musl" "linux-armv6-musl" "linux-armv7l-musl" "linux-arm64-musl" "linux-arm64" "linux-x86_64-full")
linux_hosts=("arm" "arm" "arm" "arm" "arm64" "amd64" "amd64")
current_dir=$(pwd)
parent_dir=$(dirname "$current_dir")

echo "Stage 1. Prepare images with pcap library"

for i in "${!linux_images[@]}"; do
  image=${linux_images[$i]}
  arch=${linux_archs[$i]}
  host=${linux_hosts[$i]}
  echo "Checking if image: $image exists..."
  if docker image inspect "$image" > /dev/null 2>&1; then
    echo "Image $image already exists locally."
  else
    echo "Image $image not found. Building it now..."
    docker build --platform linux/amd64 --build-arg ARCH=$arch --build-arg HOST=$host -t $image -f Dockerfile_dockcross .
    if [ $? -eq 0 ]; then
      echo "Image $image built successfully."
    else
      echo "Failed to build image $image." >&2
      exit 1
    fi
  fi
done

### Stage 2. Build executable
build_dirs=("linux-armv5-musl" "linux-armv6-musl" "linux-armv7l-musl" "linux-armv8-musl" "linux-arm64" "linux-amd64")

for i in "${!linux_images[@]}"; do
  image=${linux_images[$i]}
  build_dir=${build_dirs[$i]}
  echo "Creating binaries for $image in $build_dir"
  docker run --platform linux/amd64 -v $current_dir:/tmp/SniffMyShit $image bash -c "apt install -y cppcheck && cd /tmp/SniffMyShit && cmake -S . -B $build_dir && cmake --build $build_dir"
done

### Stage 3. Put binaries in binaries dir
mkdir -p binaries
for i in "${!build_dirs[@]}"; do
  build_dir=${build_dirs[$i]}
  mv $build_dir/SniffMyShit binaries/SniffMyShit-$build_dir
done