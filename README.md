# vpn setup

Corporate VPN is awful, how to avoid using it except when absolutely necessary.

Make sure you have `auth.env`

    USERNAME=
    PASSWORD=
    SERVER=

## avoiding all this bullshit

Just run the auth stage

    docker compose up auth

Then run openconnect manually

    . ./config.env
    sudo openconnect --cookie=$OPENCONNECT_AUTH_COOKIE \
        --servercert=$OPENCONNECT_AUTH_SERVERCERT \
        --server $OPENCONNECT_AUTH_SERVER

Stop reading now

## but i want my life to be difficult

Ok you hate your VPN, I get it.

We're going to be running VPN in an isolated container, with a SOCKS/HTTP proxy

IMPORTANT: run this to allow namespace switching

    sudo setcap cap_sys_admin,cap_sys_ptrace,cap_net_admin+ep $(which nsenter)

Docker compose brings up the whole thing

    docker compose up auth # still run separately, for reasons
    docker compose up vpn proxy -d

These zsh aliases make using this easier

    alias -g vpndo="nsenter --target $(docker inspect --format '{{.State.Pid}}' vpn-vpn-1) --net --setuid $(id -u)"
    alias -g pp="https_proxy=http://localhost:8118 http_proxy=http://localhost:8118"

Now we can test namespace usage:
    
    vpndo whoami
    vpndo id


We now have a VPN in a network namespace, a http(s) proxy on localhost:8118, and a socks5 proxy on localhost:1080

We use it either with `vpndo` for shell commands, or http/socks proxies for applications

We can `vpndo zsh` to enter a shell in which everything will use the VPN.

Test it out

    $ curl ifconfig.co # no vpn
    159.xxx.xxx.xxx 

    $ vpndo curl ifconfig.co # vpn via network namespace
    8.xxx.xxx.xxx 
    
    $ pp curl ifconfig.co # vpn via http proxy
    8.xxx.xxx.xxx 

    $ curl --socks5 localhost:1080 ifconfig.co # vpn ip via socks
    8.xxx.xxx.xxx 

    $ pp python test.py # look it works for python too
    Checking external IP address...
    IP Address: 8.....
    Country: United States
    City: Unknown

    $ vpndo zsh # enter a shell in the vpn network namespace
    $ curl ifconfig.co # now everything is in the vpn
    8.......

Use a separate browser for vpn, or configure a specific firefox container.
