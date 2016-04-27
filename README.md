Nginx krisp(korea isp) module
==========

[![License](http://img.shields.io/badge/license-BSD-brightgreen.svg)](https://github.com/vozlt/nginx-module-krisp/blob/master/LICENSE)

Nginx krisp(korea isp) module

## Dependencies
* [nginx](http://nginx.org)
* [libkrisp](http://svn.oops.org/wsvn/OOPS.libkrisp)
 * [libipcalc](http://svn.oops.org/wsvn/OOPS.libipcalc)
 * [sqlite3](http://www.sqlite.org)

## Compatibility
* 1.7.x (last tested: 1.7.8)
* 1.6.x (last tested: 1.6.2)

Earlier versions is not tested.

## Installation

1. Clone the git repository.

  ```
  shell> git clone git://github.com/vozlt/nginx-module-krisp.git
  ```

2. Add the module to the build configuration by adding 
  `--add-module=/path/to/nginx-module-krisp`

3. Build the nginx binary.

4. Install the nginx binary.

## Synopsis

```Nginx
http {
    krisp_database                  /usr/share/krisp/krisp.dat;
    krisp_database_interval         3600;
    krisp_realip_from               10.10.10.0/24;
    krisp_realip_header             X-Forwarded-For;
    krisp_realip_recursive          on;
}
```

## Description
This is an Nginx module that create new variables with values depending on
the client IP address, using the precompiled libkrisp databases(libkrisp-data).
Krisp data is combined data that is geoip(country + city + organization) and more detail korea's isp information.
This module is mixed with ngx_http_realip_module.c from nginx-1.7.8.
If use the krisp_realip_* setting, does not need to load the builtin module(ngx_http_realip_module.c).

## Directives

### krisp_database

-   | - 
--- | ---
**Syntax**  | krisp_database *\<path-to-krisp-database-file\>*
**Default** | -
**Context** | http

Description: The path of krisp database.

The following variables are available when using this database:

* $krisp_check_ip
 * requested ip address.
* $krisp_isp_code
 * isp(organization) code, for example, "KORNET", "BORANET".
* $krisp_isp_name
 * isp(organization) name, for example, "주식회사 케이티", "주식회사 엘지유플러스"
* $krisp_country_code
 * two-letter country code, for example, "KR", "US".
* $krisp_country_name
 * country name, for example, "Korea, Republic of", "United States".
* $krisp_original_ip
 * original client ip address.

### krisp_database_interval

-   | - 
--- | ---
**Syntax**  | krisp_database_interval \<*second*\>
**Default** | 0
**Context** | http

Description: The krisp database's reload interval second.

### krisp_realip_from

-   | - 
--- | ---
**Syntax**  | krisp_realip_from [*address\|CIDR\|*unix:]
**Default** | -
**Context** | http, server, location

Description: Defines trusted addresses that are known to send correct replacement addresses. If the special value unix: is specified, all UNIX-domain sockets will be trusted.(=set_real_ip_from)

### krisp_realip_header

-   | - 
--- | ---
**Syntax**  | krisp_realip_header [*field*\|X-Real-IP\|X-Forwarded-For\|proxy_protocol]
**Default** | -
**Context** | http, server, location

Description: Defines a request header field used to send the address for a replacement.(=real_ip_header)

The following variables are available when using this header field:

* $krisp_original_ip
 * original client ip address.

### krisp_realip_recursive

-   | - 
--- | ---
**Syntax**  | krisp_realip_recursive [on\|off]
**Default** | -
**Context** | http, server, location

Description: If recursive search is disabled, the original client address that matches one of the trusted addresses is replaced by the last address sent in the request header field defined by the real_ip_header directive. If recursive search is enabled, the original client address that matches one of the trusted addresses is replaced by the last non-trusted address sent in the request header field.(=real_ip_recursive)

## Author
YoungJoo.Kim(김영주) [<vozltx@gmail.com>]
