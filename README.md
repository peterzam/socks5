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
  -up int
        up speed in megabits
  -down int
        down speed in megabits
```

## Container :
Build the containerfile first
```
docker run -d --name socks5 -p 1080:1080 peterzam/go-socks5-server -user=<PROXY_USER> -pass=<PROXY_PASSWORD> -up=<PROXY_UP_LIMIT> -down=<PROXY_DOWN_LIMIT>
```
Leave `PROXY_USER` and `PROXY_PASSWORD` empty for skip authentication options while running socks5 server.

### List of all supported config parameters

|ENV variable|Type|Default|Description|
|------------|----|-------|-----------|
|PROXY_USER|String|EMPTY|Set proxy user (also required existed PROXY_PASS)|
|PROXY_PASSWORD|String|EMPTY|Set proxy password for auth, used with PROXY_USER|
|PROXY_INF|String|"lo"|Set route Interface inside docker container|
|PROXY_PORT|String|1080|Set listen port for application inside docker container|
|PROXY_UP_LIMIT|Int|0|Set upload speed limit inside docker container|
|PROXY_DOWN_LIMIT|Int|0|Set download speed inside docker container|

<hr>

## Test running service

Without authentication

```curl --socks5 <server ip>:1080  http://ifconfig.io```

With authentication

```curl --proxy socks5://<PROXY_USER>:<PROXY_USER>@<server ip>:1080 ifconfig.io ```

--- 

## Credits
https://github.com/gerritjvv/tcpshaper  
https://github.com/armon/go-socks5