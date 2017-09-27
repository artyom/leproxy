Command leproxy implements https reverse proxy with automatic Letsencrypt
usage for multiple hostnames/backends

Install:

	go get github.com/artyom/leproxy	

Run:

	leproxy -addr :https -map /path/to/mapping.yml -cacheDir /path/to/letsencrypt

`mapping.yml` contains host-to-backend mapping, where backend can be specified as:

 * http/https url for http(s) connections to backend *without* passing "Host"
   header from request;
 * host:port for http over TCP connections to backend;
 * absolute path for http over unix socket connections;
 * @name for http over abstract unix socket connections (linux only);
 * absolute path with trailing slash to serve files from given directory.

Example:

	subdomain1.example.com: 127.0.0.1:8080
	subdomain2.example.com: /var/run/http.socket
	subdomain3.example.com: @abstractUnixSocket
	uploads.example.com: https://uploads-bucket.s3.amazonaws.com
	static.example.com: /var/www/

Note that when `@name` backend is specified, connection to abstract unix socket
is made in a manner compatible with some other implementations like uWSGI, that
calculate addrlen including trailing zero byte despite [documentation not
requiring that](http://man7.org/linux/man-pages/man7/unix.7.html). It won't
work with other implementations that calculate addrlen differently (i.e. by
taking into account only `strlen(addr)` like Go, or even `UNIX_PATH_MAX`).
