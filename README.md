# DNS blocklist creater written in rust

This project creates zone entries for each blocked domain on various blocklists.
They get redirected to either 127.0.0.1/::1 (default) or a sinkhole of your choosing.

To manually block a certain domain just extend the blocklist entry:
    blocklist:
      - heise.de

## Configure
1. Install libcurl-dependencies (libssl-dev / pkg-config)
2. Copy config.yml to /etc/blocker/ (needs to be created) and change the settings accordingly.
3. Add an include statement for the named_path value in your named.conf.
4. Periodically execute created binary on your bind9 server.

The binary automatically reloads the bind9 daemon so please use with caution.

### Beware
There is currently no syntax checking for the named.conf.blocklists.

