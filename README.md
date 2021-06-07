# simple-http-server
A variant of Tinyhttpd.

Created November 1999 by J. David Blackstone.

Modified June 2021 by Fumiama(源文雨)

# Features

1. Serve files
2. CGI
3. Listen on `ipv6`
4. Multi-thread

# Compile

```bash
git clone https://github.com/fumiama/simple-http-server.git
cd simple-http-server
mkdir build
cd build
cmake ..
make
make install
```

# Command line usage

```bash
simple-http-server -d port chdir
```

- **-d** - run as daemon
- **port** - bind server on this port (0 for a random one)
- **chdir** - change root dir to here