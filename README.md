# mod\_authz\_ts\_cap

Apache httpd authorization for tailscale capabilities access.

## What it does

When you run Apache httpd on a machine in a tailscale VPN (some words about what that is [below](#about_tailscale)), you can manage access to sites or specific
resources based on where connections come from. For example, if you installed tailscale with login `your-id@github`:

```
<VirtualHost *:443>
  <Location />
    Require ts-cap ServerName
  </Location>
  ...
</VirtualHost>
```

means that only tailscale connections from one of your machines/phones you added have access here.

This is very convenient since there is no need for additional logins. No connection coming from someone/somewhere else 
will have access here.

## Status

Experimental. Available only on Linux machines (or where tailscale provides a unix domain socket). Requires `libcurl` and `libjansson` to build. Should work with any recent Apache httpd 2.4.x.


## Authorizations

The module adds one authorization directive right now:

1. `ts-cap`: checks the `ServerName` of the `VirtualHost` where this request is coming from and checks if the tailscale capibities include it.

## Tailscale Capabilities



## Configuration

Normally nothing. Just load the module into the server and add `Require` directives where appropriate. Should you
be on a platform where the tailscale unix domain socket is not found, you can configure

```
AuthTailscaleURL file://localhost/var/lib/anotherpath/tailscale.socket
```

This configuration is recommended to be done globally.

Tailscale information is cached per connection for a short while. This is to prevent lookups for 
each request. The default timeout for such information is 1 second. You can change that by configuring

```
AuthTailscaleCacheTimeout 30s
```


## How it works

On each machine, there is a `tailscale` demon running which does the routing and encryption. When it accepts network packets, it knows who encrypted them or it does not allow them in. Simplified, a packet from address `a.b.c.d` has to use a specific key and that key belongs to user `XYZ`. Only if `XYZ` is granted access into you tailscale network, will this data ever appear.

The tailscale demon has a local HTTP API, accessible on Linux via a unix domain socket, where one may ask which user is behind a remote address and port. `mod_authz_ts_cap` uses this feature to find the tailscale capabilities behind an incoming HTTP request.

## Credits

This is a fork of and based upon the work by @icing (Stefan Eissing) in [https://github.com/icing/mod_authnz_tailscale](https://github.com/icing/mod_authnz_tailscale)

