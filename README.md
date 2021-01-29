```
usage: focal-standalone-init [-h] -user USERNAME -ssh SSHPUBKEY -mail EMAIL -host HOSTNAME [--locale LOCALE] [--timezone TIMEZONE] [--harden-network] [--install-postfix] [--install-docker] [--install-netdata] [-v]

optional arguments:
  -h, --help            show this help message and exit
  --locale LOCALE       host locale, defaults to: "en_US.UTF-8"
  --timezone TIMEZONE   host timezone, defaults to: "Europe/Berlin"
  --harden-network      harden network kernel settings
  --install-postfix     install postfix (as local only mta)
  --install-docker      install docker-ce
  --install-netdata     install netdata
  -v, --verbose         verbose log output, set log level to debug

required arguments:
  -user USERNAME, --username USERNAME
                        admin username
  -ssh SSHPUBKEY, --sshpubkey SSHPUBKEY
                        admin public ssh key
  -mail EMAIL, --forward-mail EMAIL
                        admin email address (if mta is installed, admin and root mail get forwarded here)
  -host HOSTNAME, --hostname HOSTNAME
                        hostname (for mta to work, this should be a domain pointing to this box)
```
---
```
sudo ./focal-standalone-init.py \
--username hub \
--sshpubkey "ssh-ed25519 AAAA....snWK hub@desktop" \
--forward-mail some@mail.com \
--hostname mydomain.com \
--locale en_US.UTF-8 \
--timezone Europe/Berlin \
--harden-network \
--install-postfix \
--install-docker \
--install-netdata \
--verbose
```
