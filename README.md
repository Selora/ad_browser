# ad_browser
AD LDAP dumper

This project is a PoC to connect to an active directory LDAP and pull
useful information for recon. Based a bit on https://github.com/dirkjanm/ldapdomaindump (thanks man, you
don't know how many time I used your tool!). It is a bit less intensive on
memory and supports about the same features.

```
python ad_recon.py 192.168.56.100 ENTERPRISE Administrator -H '<lm or 0000...>:<NTLM>'
python ad_recon.py 192.168.56.100 ENTERPRISE Administrator -p <password>
```

Needs python3
