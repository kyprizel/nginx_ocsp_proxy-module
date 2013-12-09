Description
===========

**nginx_ocsp_proxy-module** - module for OCSP request and response processing designed to allow response caching using
[srcache-nginx-module](https://github.com/agentzh/srcache-nginx-module) and [memc-nginx-module](https://github.com/agentzh/memc-nginx-module).

Status
======

Working alpha

Installation
============

Grab the nginx source code from [nginx.org](http://nginx.org/), for example, the version 1.5.7 (see nginx compatibility).
Grab [srcache-nginx-module](https://github.com/agentzh/srcache-nginx-module) and [memc-nginx-module](https://github.com/agentzh/memc-nginx-module).
Build the source with this module:

    wget 'http://nginx.org/download/nginx-1.5.7.tar.gz'
    tar -xzvf nginx-1.5.7.tar.gz
    cd nginx-1.5.7/
    ./configure --with-debug --add-module=/path/to/srcache-nginx-module \
                        --add-module=/path/to/memc-nginx-module \
                        --add-module=/path/to/nginx_ocsp_proxy-module

    make
    make install

Modules order does matter!

Compatibility
=============

Module was tested with nginx 1.5+, but should work with 1.4+.

Example configuration
=====================

    upstream my_memcached {
        server 127.0.0.1:11211;
    }

    server {
        listen       80;
        server_name  localhost;
        client_max_body_size 256k;

        location /memc {
            internal;

            set $memc_key $arg_key;
            set $memc_exptime $arg_exptime;

            memc_pass my_memcached;
        }

        location / { 
            ocsp_proxy on;
            set $key $ocsp_serial;

            srcache_methods GET POST;

            srcache_fetch GET /memc key=$key;
            srcache_fetch_skip $ocsp_response_skip_caching;

            srcache_store PUT /memc key=$key&exptime=$ocsp_response_cache_time;
            srcache_store_statuses 200;

            srcache_store_skip_body $ocsp_response_skip_caching;
            srcache_store_hide_header Date;

            proxy_pass http://ocsp.someca.com;
            proxy_ignore_client_abort on;
        }
    }


Sources
=======

Available on github at [/kyprizel/nginx_ocsp_proxy-module](https://github.com/kyprizel/nginx_ocsp_proxy-module).

TODO
====

*   Code review
*   Testing

Bugs
====

Feel free to report bugs and send patches to eldar@kyprizel.net
or using [github's issue tracker](https://github.com/kyprizel/nginx_ocsp_proxy-module/issues).

Copyright & License
===================

Copyright (c) 2013, Eldar Zaitov
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

* Neither the name of the {organization} nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
