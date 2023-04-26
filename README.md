# fx-libpcap - Axellio modified libpcap with support for PacketXpress reception

## Build HOWTO

### Building an RPM
```
cd libpcap
make -f Makefile-rpm
```

### Building and installing locally
```
cd libpcap
./configure --prefix=/usr --enable-axellio
make
sudo make install
sudo ldconfig
```
