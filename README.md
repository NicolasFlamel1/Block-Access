# Block Access

### Description
Nginx module that allows blocking HTTP requests based on the request's IP address, URL path, top-level domain, HTTP method, and HTTP headers.

### Installing
Run the following commands to build and install this module.
```
wget "https://github.com/NicolasFlamel1/Block-Access/archive/refs/heads/master.zip"
unzip "./master.zip"
wget "https://nginx.org/download/nginx-$(nginx -v 2>&1 | awk '{print $3}'  | awk -F'/' '{print $2}').tar.gz"
tar -xf "./nginx-$(nginx -v 2>&1 | awk '{print $3}'  | awk -F'/' '{print $2}').tar.gz"
cd "./nginx-$(nginx -v 2>&1 | awk '{print $3}'  | awk -F'/' '{print $2}')"
echo $(nginx -V 2>&1 >/dev/null | grep -oP '(?<=^configure arguments: ).*?(?= --add-dynamic-module)') --add-dynamic-module="../Block-Access-master" | xargs "./configure"
make modules
sudo mv "./objs/ngx_http_block_access_module.so" "/usr/share/nginx/modules/"
```

Add the following line to the `top-level` context in your Nginx configuration file, `/etc/nginx/nginx.conf`, to enable this module.
```
load_module modules/ngx_http_block_access_module.so;
```

### Usage
This module provides the following directives that can be used in a `location` context.
1. `block_access`: This directive accepts a parameter with the request's URL.
2. `block`: This directive accepts a parameter for an IP address or two parameters for an IP address range that will be blocked.
3. `unblock`: This directive accepts a parameter for a URL path that will be unblocked.
4. `allow_top_level_domain`: This directive accepts a parameter for a top-level domain that will be unblocked.
5. `allow_method`: This directive accepts a parameter for an HTTP method that will be unblocked.
6. `require_header`: This directive accepts a parameter for a HTTP header that must exists for the request to not be blocked.

For example, the following demonstrates how to prevent a reverse proxy from making requests to any reserved IP address and to limit it to only making AJAX POST requests to `/index.html` at `.com` domain names.
```
location ~ ^/proxy/(https?)://?(.+/.*)$ {

	resolver 127.0.0.53;
	resolver_timeout 30s;
	
	block "255.255.255.255";
	block "0.0.0.0" "0.255.255.255";
	block "10.0.0.0" "10.255.255.255";
	block "100.64.0.0" "100.127.255.255";
	block "127.0.0.0" "127.255.255.255";
	block "169.254.0.0" "169.254.255.255";
	block "172.16.0.0" "172.31.255.255";
	block "192.0.0.0" "192.0.0.255";
	block "192.0.2.0" "192.0.2.255";
	block "192.88.99.0" "192.88.99.255";
	block "192.168.0.0" "192.168.255.255";
	block "198.18.0.0" "198.19.255.255";
	block "198.51.100.0" "198.51.100.255";
	block "203.0.113.0" "203.0.113.255";
	block "224.0.0.0" "239.255.255.255";
	block "240.0.0.0" "255.255.255.254";
	block "::";
	block "::1";
	block "::ffff:0.0.0.0" "::ffff:255.255.255.255";
	block "::ffff:0:0.0.0.0" "::ffff:0:255.255.255.255";
	block "64:ff9b::0.0.0.0" "64:ff9b::255.255.255.255";
	block "100::" "100::ffff:ffff:ffff:ffff";
	block "2001::" "2001::ffff:ffff:ffff:ffff:ffff:ffff";
	block "2001:20::" "2001:2f:ffff:ffff:ffff:ffff:ffff:ffff";
	block "2001:db8::" "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";
	block "2002::" "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
	block "fc00::" "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
	block "fe80::" "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
	block "ff00::" "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
	unblock /index.html;
	allow_top_level_domain ".com";
	allow_method POST;
	require_header X-Requested-With "XMLHttpRequest";
	block_access $1://$2;
	
	proxy_pass $1://$2$is_args$args;
}
```
