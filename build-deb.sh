# By🇭🇷PhonkAlphabet
#!/bin/bash
set -e

VERSION="1.3.0"
PACKAGE_NAME="blueteam-aio"
ARCH="amd64"

# Create build directory
BUILD_DIR="/tmp/blueteam-build"
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR/DEBIAN
mkdir -p $BUILD_DIR/opt/blueteam-aio
mkdir -p $BUILD_DIR/etc/systemd/system
mkdir -p $BUILD_DIR/usr/bin
mkdir -p $BUILD_DIR/var/lib/blueteam-aio/models
mkdir -p $BUILD_DIR/var/lib/blueteam-aio/deception
mkdir -p $BUILD_DIR/opt/blueteam-aio/bin
mkdir -p $BUILD_DIR/opt/blueteam-aio/src/ebpf

# Copy files
cp -r src $BUILD_DIR/opt/blueteam-aio/
# In production, llama-cli would be copied here. For this build, we create a symlink or placeholder if not present.
touch $BUILD_DIR/opt/blueteam-aio/bin/llama-cli
chmod +x $BUILD_DIR/opt/blueteam-aio/bin/llama-cli
# Copy eBPF source
cp src/modules/kernel_monitor.c $BUILD_DIR/opt/blueteam-aio/src/ebpf/ 2>/dev/null || touch $BUILD_DIR/opt/blueteam-aio/src/ebpf/kernel_monitor.c
cp -r plugins $BUILD_DIR/opt/blueteam-aio/ 2>/dev/null || true
cp debian/control $BUILD_DIR/DEBIAN/
cp debian/postinst $BUILD_DIR/DEBIAN/
cp debian/prerm $BUILD_DIR/DEBIAN/
cp debian/blueteam-aio.service $BUILD_DIR/etc/systemd/system/

# Create wrapper script
cat > $BUILD_DIR/usr/bin/blueteam-aio << 'WRAPPER'
#!/bin/bash
exec /usr/bin/python3 /opt/blueteam-aio/src/daemon/core.py "$@"
WRAPPER
chmod +x $BUILD_DIR/usr/bin/blueteam-aio

# Build .deb
mkdir -p dist
dpkg-deb --build $BUILD_DIR dist/${PACKAGE_NAME}-${VERSION}-${ARCH}.deb

echo "✓ Package built: dist/${PACKAGE_NAME}-${VERSION}-${ARCH}.deb"
ls -lh dist/
