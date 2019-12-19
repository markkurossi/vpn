# vpn
Virtual Private Network for Everything

## Application and Browser Independent Ad Blocker

Start the vpn application with a domain blacklist file:

    $ sudo ./vpn -blaclist test.bl -i

The _-i_ flag starts the application in interactive mode:

![Interactive ad blocker](adblock.png)

## DNS Server Configuration

### Query DNS Servers

    $ scutil --dns | grep nameserver

### Set DNS Servers

    $ networksetup -setdnsservers Wi-Fi 192.168.192.254
    $ networksetup -setdnsservers Wi-Fi 192.168.99.1

### Flush DNS Cache

This information is from [help.dreamhost.com](https://help.dreamhost.com/hc/en-us/articles/214981288-Flushing-your-DNS-cache-in-Mac-OS-X-and-Linux).

#### OSX 12 (Sierra) and later

    $ sudo killall -HUP mDNSResponder; sudo killall mDNSResponderHelper; sudo dscacheutil -flushcache

#### OS X 11 (El Capitan) and OS X 12 (Sierra)

    $ sudo killall -HUP mDNSResponder
