Command leproxy implements https reverse proxy with automatic Letsencrypt
usage for multiple hostnames/backends

Install:

	go get github.com/artyom/leproxy	

Run:

	leproxy -addr :https -map /path/to/mapping.yml -cache /path/to/letsencrypt.cache

`mapping.yml` contains host-to-backend mapping, where backend can be specified as:

 * http/https url for http(s) connections to backend *without* passing "Host"
   header from request;
 * host:port for http over TCP connections to backend;
 * absolute path for http over unix socket connections;
 * absolute path with trailing slash to serve files from given directory.

Example:

	subdomain1.example.com: 127.0.0.1:8080
	subdomain2.example.com: /var/run/http.socket
	uploads.example.com: https://uploads-bucket.s3.amazonaws.com
	static.example.com: /var/www/
