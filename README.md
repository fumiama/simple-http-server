<div align="center">
  <img src=".github/shinsako.jpg" width = "360" height = "360" alt="Shinsako"><br>
  <h1>simple-http-server</h1>
  A variant of Tinyhttpd.<br><br>
</div>

> Created November 1999 by J. David Blackstone.
> 
> Modified June 2021 by Fumiama(源文雨)

## Protocol
A necessary subset of `HTTP 1.0` with following options of request header being supported.

### From client
- Content-Length

### From server
- Content-Length
- Content-Type (only support text/plain image/x-icon text/css text/html)
- Server

### Code
- 200 OK
- 400 BAD REQUEST
- 404 NOT FOUND
- 500 Internal Server Error
- 501 Method Not Implemented

## Features
1. Serve files
2. CGI
3. Listen on `ipv6`
4. Listen on unix socket
5. Multi-thread

## Compile
```bash
git clone https://github.com/fumiama/simple-http-server.git
cd simple-http-server
mkdir build
cd build
cmake ..
make
make install
```

## Command line usage
```bash
simple-http-server [-h] [-d] [-p <port|unix socket path>] [-r <rootdir>] [-u <uid>]
```

- **-h**:  display this help.
- **-d**:  run as daemon.
- **-p**:  if not set, we will choose a random port.
- **-r**:  http root dir.
- **-u**:  run as this uid.

## CGI usage
When you put an executable file into the web path, the server will call `execl` to run it while passing 3 parameters as below

```c
argv[0] = path;   //Path of the executable file
argv[1] = method; //request method (GET/POST)
argv[2] = query_string;   //the query string, like "a=1&b=2&c=3"
```

The server will read a `4 bytes` unsigned integer from pipe, indicating the `length` of the remaining content. Then it will send `length` bytes of data to the client directly with nothing being decorated, which means that you need to assemble the HTTP header by yourself.

Here is a CGI example [CMoe-Counter](https://github.com/fumiama/CMoe-Counter)

And its realization is here:

<div align=center> <a href="#"> <img src="http://cmoe.azurewebsites.net/cmoe?name=shttps&theme=gb" /> </a> </div>
