This is an example, how one may organize a mass deployment of Letsencrypt (LE)
certificates. Below we use '+' as an alias to pfexec or sudo or whatever
utility gives you the higher privileges to execute the task successfully.


webserver.my.do.main
====================
The machine, which runs e.g. a web server, which finally handles all requests
from ACME servers and provides access to issued certificates.

We assume, that the pool1/zfs has its mountpoint property set to '/data'.
and the user 'admin' manages the data. /data/letsencrypt/certs/ will contain
all issued certificates and __nothing else__, /data/letsencrypt/answers will
be used as RESPONSE_DIR, where acme-ksh will store the answers to ACME server
challenges - the proof, that one has control over the related domain.

Setup the ZFS and share it to the zone (10.1.2.4), which runs acme-ksh
per cronjob day-by-day:
```
ZFS=pool1/data/letsencrypt
zpool create ${ZFS}
+ chown admin:staff /data/letsencrypt
mkdir /data/letsencrypt/{answers,certs}

ADMINS+=':@10.1.2.4/31'			# leadmhost.my.do.main, leadmhost2.my.domain
+ zfs set share.nfs.sec=sys ${ZFS}
+ zfs set share.desc="LE Webspace" ${ZFS}
+ zfs set share.nfs.sec.sys.rw=${ADMINS} ${ZFS}
+ zfs set share.nfs.sec.sys.root=${ADMINS} ${ZFS}
+ zfs set share.nfs=on ${ZFS}
```

Point Apache httpd to the right directory by adding the following snippet to
the [virtual] site config:
```
<IfModule !alias_module>
    LoadModule	alias_module	libexec/mod_alias.so
</IfModule>
Alias "/certs/" "/data/letsencrypt/certs/"
Alias "/.well-known/acme-challenge/" "/data/letsencrypt/answers/"
<Directory "/data/letsencrypt">
	Options -Indexes -Includes -MultiViews
	Require all granted
</Directory>
```

And finally restart the webserver:
```
svcadm disable -st apache24 ; svcadm enable -s apache24
```
or e.g. on Linux
```
+ systemctl stop apache24; + systemctl start apache24
```


On any other webserver
======================
Redirect /.well-known/acme-challenge/ an every host you wanna get a certificate
for to the webserver above with the same path, e.g. using apache httpd, nginx,
or anything else, which listens on port 80 and is able to answer such request
with a redirect.

E.g. on Apache httpd one may add the following snippet to the [virtual] site
config:
```
Define LE_HOST webserver.my.do.main:80
Define LE_PREFIX .well-known/acme-challenge
```

And where your redirect rules start:
```
<IfModule rewrite_module>
    RewriteEngine On

    # LetsEncrypt
    RewriteCond %{REQUEST_FILENAME} ^/${LE_PREFIX}/
    RewriteRule ^/${LE_PREFIX}/(.*) http://${LE_HOST}/${LE_PREFIX}/$1 [L,R=301]
</IfModule>
<Location /${LE_PREFIX}>
    Require all granted
</Location>
```
And restart the webserver as shown above.


leadmhost.my.do.main
====================
We assume, that the user 'admin' manages the certificates and has the same UID
on webserver.my.dom.main as on this machine.


firewall setup
--------------
Make sure, that the firewall on both machines allow NFS traffic to flow.
The easiest way ist to use NFSv4 and just care about port 2049. E.g. with
ipfilter:

```
pass out quick proto tcp to ${NFS_SERVER} port = nfsd flags S/SA keep state keep frags
pass in quick proto tcp from ${NFS_CLIENTS} to port = nfsd flags S keep state keep frags
# and if the implementation is a little bit buggy add
pass in quick proto tcp from ${NFS_SERVER} port = nfsd flags A/ARFS
pass in quick proto tcp from ${NFS_SERVER} port = nfsd flags R/ARFS
pass in quick proto tcp from ${NFS_SERVER} port = nfsd flags AF/ARFS
pass out quick proto tcp to ${NFS_SERVER} port = nfsd flags A/ARFS
pass out quick proto tcp to ${NFS_SERVER} port = nfsd flags R/ARFS
pass out quick proto tcp to ${NFS_SERVER} port = nfsd flags AF/ARFS
```

Finally make sure, that your firewall allows outgoing connections to port 443.
Unfortunately Letsencrypt admins prefer security by obscurity and do not use
fixed IPs, so that one can further narrow this big hole (IMHO changing IPs
are really stupid, and just put a big burden on consumer's shoulders and buys
the provider almost nothing ...).  E.g.:

```
pass out quick proto tcp to any port = https flags S keep state
```

automounter setup
-----------------
Use the automounter to mount the required directory automatically to reduce
traffic, dependencies, etc... So make sure /etc/auto_master contains the entry

```
/net	-hosts	-nosuid,nobrowse
```

and check, whether it works:

```
ls -al /net/webserver/data/letsencrypt/
touch /net/webserver/data/letsencrypt/answers/foo
rm /net/webserver/data/letsencrypt/answers/foo
touch /net/webserver/data/letsencrypt/certs/foo
rm /net/webserver/data/letsencrypt/certs/foo
```

If you do not have the luxury to host a Solaris 11+ or Illumos based machine, you may use any other NFS capable machine and mount it e.g. via /etc/fstab or an automounter direct map (unfortunately on Linux the '/net -hosts ...' usually does not work, and where it is claimed to work, it is a real pain how it works - really no fun).  


acme.ksh:
---------
acme-ksh stores all management data incl. unencrypted private keys in the
config directory, which defaults to `~/.acme2/`. It gets created on the first use
automagically. So e.g. the first thing to do is, to see the inital config and
secure it as needed:

```
acme.ksh -c config
chmod 700 ~/.acme2
```

Make sure, only authorized persons have access to this directory (or the
directory you decided to use instead of it). Sharing this to other machines
is not recommended at all! Keep it secure!

You can customize the defaults by creating a `~/.acme2/le.conf` file and add the
desired key=value pairs (it gets handled as ksh snippet, so you can make use
of its features, but that's rarely needed). For more information see:

```
acme.ksh -h
acme.ksh -H LE_ENV
acme.ksh -H getConfig		# for implementation details
```

So lets customize:

```
cat >~/.acme2/le.conf<<EOF
RESPONSE_DIR='/net/webserver/data/letsencrypt/answers'
CERT_DIR='/net/webserver/data/letsencrypt/certs'
CA='le'		# use the production site instead of 'test' by default
EOF
```

Now create your account on Letsencrypt:

```
acme.ksh -c register -e admin+le@do.main
```
This stores related information in the config directory under `a-${account}.*` .
If not explicitly specified, the account named 'default' will be used for
this and all other operations. Note that this "account" has nothing to do
with your OS or `/etc/passwd`. It is just a name to refer to/find easily keys
and URLs required to manage your certificates.


day-by-day
----------
To obtain a certificate for a domain and its aliases for the _first time_,
just run:

```
acme.ksh -c cert -d www.my.do.main,www2.my.do.main,www3.my.do.main
```

Note that certificate related information get stored in the config directory
under `r-www.my.do.main.*` and domain specific data under `d-${domain}.*` .

So on success you should have a `~/.acme2/le/r-www.my.do.main.crt` - the SSL
Certificate alias "public key" for your application. Furthermore there should
be a `~/.acme2/le/r-www.my.do.main.key` - the per default unencrypted private
key for your certificate. Both are PEM encoded. You need to copy both files to
the appropriate places, possibly  the certificate to
`/etc/ssl/certs/www-my-do-main.crt` and the private key to
`/etc/ssl/private/www-my-do-main.key` and run the command to update the hashes,
e.g. on Solaris `svcadm refresh ca-certificates`,
on Ubuntu `+ update-ca-certificates` or just make in the related app directory.
Please ready you app documentation for more details.

Once you have these files in place, you probably need to restart your app.

Now you can setup a cronjob to re-new all certificates when needed:

```
50 23 * * 3	~/etc/acem-ksh -c renew -d all
```

acme.ksh will re-new all related domain authorizations (see `d-${domain}.*` files)
and finally request a new certificate, if e.g. `r-www.my.do.main.crt` is still in
place and expires in less than 30 days. If the related
`r-www.my.do.main.key` is missing, a new one gets generated automatically. Do
not forget to copy over the new key as well, because the new certificate does
not work with the old key.

If you use `-d all` in your cronjob, acme.ksh checks all readable `r-*.crt` files
in the configuration directory and re-news them as needed.

Because of the `CERT_DIR='/net/letsencrypt/data/letsencrypt/certs'`
customization, the new certificate gets also copied to
`/net/le/data/letsencrypt/certs/www.my.do.main.crt` and thus one can setup
a cronjob on the related machines to pull the new certificate e.g. via
`'wget -O /etc/ssl/certs/app.crt https://webserver.do.main/certs/www.my.do.main.crt'` and restart the app if needed. You may use or adjust [le-cert-update.ksh](../le-cert-update.ksh) for this job.

NOTE that the private key gets reused by default, and thus there is **no need at
all** to publish/expose any private key via web or any other media. When you
lost/drop the old key, just let acme.ksh create a new one and than copy it via
scp to the secure place, where your application is expecting it.


standalone mode
---------------
Last but not least: Since acme.ksh has a minimalistic webserver embedded, one
may even run it directly on the machine `webserver`, when no app else is
listening on port 80, or the port redirect rules on all machines point to.
It doesn't need to run all the time, because LE servers
check the responses to challenges (the proof that you own the domain) usually within
10 seconds, so wrt. ACME there is no need to run the webservice, when acme.ksh
is not running. The small drawback is, that one needs to have python with the
six module for 2.x to 3.x compatibility and its standard library with the
basic http server class installed. Today this is the case on almost all, even
on very minimalistic installations, so should not really hurt. The internal
server is not very efficient, but usually far more than sufficient as needed
for handling ACME requests. Finally, because it is so minimalistic, it might or
might not have bugs, which may allow more, than we expect. So take care,
especially when running as root or with higher privileges!
