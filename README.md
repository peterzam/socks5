# SOCKS5 Library  
### The project is forked from armon/go-socks5   
## Run server using compiled binary :
```
Usage of socks5-server
  -user string
        proxy username
  -pass string
        proxy password
  -inf string
        proxy out interface (default "lo")
  -port int
        proxy port (default 1080)
```

## Container :
Build the containerfile first
```
docker run -d --name socks5 -p 1080:1080 peterzam/go-socks5-server -user=<PROXY_USER> -pass=<PROXY_PASSWORD>
```
Leave `PROXY_USER` and `PROXY_PASSWORD` empty for skip authentication options while running socks5 server.

### List of all supported config parameters

|ENV variable|Type|Default|Description|
|------------|----|-------|-----------|
|PROXY_USER|String|EMPTY|Set proxy user (also required existed PROXY_PASS)|
|PROXY_PASSWORD|String|EMPTY|Set proxy password for auth, used with PROXY_USER|
|PROXY_INF|String|"lo"|Set route Interface inside docker container|
|PROXY_PORT|String|1080|Set listen port for application inside docker container|

<hr>

## Test running service

Without authentication

```curl --socks5 <server ip>:1080  http://ifconfig.io```

With authentication

```curl --proxy socks5://<PROXY_USER>:<PROXY_USER>@<server ip>:1080 ifconfig.io ```
