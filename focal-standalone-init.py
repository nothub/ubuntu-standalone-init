#!/usr/bin/env python3
import sys
from typing import List

if sys.version_info.major != 3 or sys.version_info.minor < 8:
    print('please run with python 3.8+', file=sys.stderr)
    sys.exit(1)

from pathlib import Path
import argparse
import glob
import logging as log
import os
import pwd
import random
import re
import shutil
import string
import subprocess as sp
import sys

TEMP_DIR = Path('/tmp/focal-standalone-init').resolve()


def apt_update():
    run_shell_command(['apt-get', 'update'])


def apt_upgrade():
    run_shell_command(['apt-get', '-qy', '--with-new-pkgs', 'upgrade'])


def apt_install(packages: list):
    run_shell_command(['apt-get', '-qy', 'install'] + packages,
                      env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})


def apt_purge(packages: list):
    run_shell_command(['apt-get', '-qy', 'purge'] + packages)


def apt_clean():
    run_shell_command(['apt-get', '-qy', 'clean']) and run_shell_command(['apt-get', '-qy', 'autoremove'])


def run_shell_command(command: list, cwd=None, env=None, pipe_input=None):
    if cwd is None:
        cwd = Path('.').resolve()
    log.debug('running: ' + str(command) + ' in: ' + str(cwd))
    if env is not None:
        log.debug('env: ' + str(env))
    if pipe_input is not None:
        log.debug('pipe input: ' + pipe_input)
    proc = sp.run(command, stdout=sp.PIPE, text=True, cwd=cwd, env=env, input=pipe_input)
    if proc.stdout is not None and has_content(str(proc.stdout)):
        log.debug('stdout: ' + str(proc.stdout))
    if proc.stderr is not None and has_content(str(proc.stderr)):
        log.debug('stderr: ' + str(proc.stderr), file=sys.stderr)
    if proc.returncode != 0:
        on_panic('exit code ' + str(proc.returncode) + ' for: ' + str(cwd) + ' ' + str(command))


def download_file(url: str, path: Path) -> Path:
    log.debug('downloading: ' + url + ' to: ' + str(path))
    delete_path_object(path)
    run_shell_command([
        'curl',
        url,
        '-o',
        str(path)
    ], cwd=TEMP_DIR)
    return Path(path).resolve()


def find_in_file(string: str, path: Path) -> bool:
    for line in read_lines(path):
        if string in line:
            return True
    return False


def read_lines(path) -> List[str]:
    if not path.is_file():
        on_panic('not a valid file: ' + str(path))
    with open(path) as file:
        lines = file.read().split('\n')
        file.close()
    return lines


def write_lines(lines: list, path: Path):
    with open(path, 'w') as file:
        for line in lines:
            file.write(line + '\n')
        file.close()


def has_content(string: str) -> bool:
    return len(remove_non_content(string)) > 0


def remove_non_content(string: str) -> str:
    return string \
        .replace('\r', '') \
        .replace('\n', '') \
        .replace('\f', '') \
        .replace('\v', '') \
        .replace('\t', '') \
        .replace(' ', '')


def add_or_replace(pattern: str, replacement: str, path: Path) -> bool:
    pattern_stripped = remove_non_content(pattern)
    replacement_stripped = remove_non_content(replacement)

    # remove trailing empty lines
    lines_in = read_lines(path)
    for line in reversed(lines_in):
        if not has_content(line):
            del lines_in[-1]
        else:
            break

    lines_out = list()
    found = False
    for line in lines_in:
        # do nothing if present
        if remove_non_content(line).startswith(replacement_stripped):
            return True
        # replace line while keeping prefix whitespaces
        if remove_non_content(line).startswith(pattern_stripped):
            prefix = re.search('^([\\t ]*).*$', line).group(1)
            lines_out.append(prefix + replacement)
            found = True
        else:
            lines_out.append(line)

    if not found:
        lines_out.append(replacement)

    write_lines(lines_out, path)

    return True


def delete_path_object(path: Path):
    if path.exists():
        if path.is_file():
            log.debug('deleting file at: ' + str(path))
            path.unlink()
        elif path.is_dir():
            log.debug('deleting directory at: ' + str(path))
            shutil.rmtree(path, ignore_errors=True)
        else:
            on_panic('unable to delete object at path: ' + str(path))


def user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
    except KeyError:
        return False
    return True


def random_string(length=20) -> str:
    return ''.join(
        random.SystemRandom().choice(string.ascii_letters + string.digits + '!?%*+-_') for _ in range(length))


def on_panic(message: str):
    log.error(message, file=sys.stderr)
    exit(1)


def parse_args():
    root_parser = argparse.ArgumentParser(prog='focal-standalone-init')
    required_parser = root_parser.add_argument_group('required arguments')

    required_parser.add_argument(
        '-user', '--username',
        action='store',
        type=str,
        required=True,
        metavar='USERNAME',
        help='admin username'
    )

    required_parser.add_argument(
        '-ssh', '--sshpubkey',
        action='store',
        type=str,
        required=True,
        metavar='SSHPUBKEY',
        help='admin public ssh key'
    )

    required_parser.add_argument(
        '-mail', '--forward-mail',
        action='store',
        type=str,
        required=True,
        metavar='EMAIL',
        help='admin email address (if mta is installed, admin and root mail get forwarded here)'
    )

    required_parser.add_argument(
        '-host', '--hostname',
        action='store',
        type=str,
        required=True,
        metavar='HOSTNAME',
        help='hostname (for mta to work, this should be a domain pointing to this box)'
    )

    root_parser.add_argument(
        '--locale',
        action='store',
        type=str,
        required=False,
        default='en_US.UTF-8',
        metavar='LOCALE',
        help='host locale, defaults to: "en_US.UTF-8"'
    )

    root_parser.add_argument(
        '--timezone',
        action='store',
        type=str,
        required=False,
        default='Europe/Berlin',
        metavar='TIMEZONE',
        help='host timezone, defaults to: "Europe/Berlin"'
    )

    root_parser.add_argument(
        '--harden-network',
        action='store_true',
        required=False,
        help='harden network kernel settings'
    )

    root_parser.add_argument(
        '--install-postfix',
        action='store_true',
        required=False,
        help='install postfix (as local only mta)'
    )

    root_parser.add_argument(
        '--install-docker',
        action='store_true',
        required=False,
        help='install docker-ce'
    )

    root_parser.add_argument(
        '--install-netdata',
        action='store_true',
        required=False,
        help='install netdata'
    )

    root_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        required=False,
        help='verbose log output, set log level to debug'
    )

    return root_parser.parse_args()


if __name__ == '__main__':

    args = parse_args()

    level = log.INFO
    if args.verbose is True:
        level = log.DEBUG
    log.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=level)

    print('--------')
    print('admin username:\t\t' + args.username.expandtabs())
    print('admin sshpubkey:\t' + args.sshpubkey.expandtabs())
    print('admin mail:\t\t' + args.forward_mail.expandtabs())
    print('--------')
    print('host name:\t\t' + args.hostname.expandtabs())
    print('host locale:\t\t' + args.locale.expandtabs())
    print('host timezone:\t\t' + args.timezone.expandtabs())
    print('--------')
    print('harden network:\t\t' + str(args.harden_network).expandtabs())
    print('install postfix:\t' + str(args.install_postfix).expandtabs())
    print('install docker:\t\t' + str(args.install_docker).expandtabs())
    print('install netdata:\t' + str(args.install_netdata).expandtabs())
    print('--------')
    print('verbose:\t\t' + str(args.verbose).expandtabs())
    print('--------')
    input('Press Enter to continue...')
    print('ᕕ( ᐛ )ᕗ\n')

    if os.geteuid() != 0:
        on_panic('This script requires root permissions.')

    if not find_in_file('DISTRIB_CODENAME=focal', Path('/etc/lsb-release').resolve()):
        on_panic('This script is inteded to be run on Ubuntu 20.04 (focal).')

    delete_path_object(TEMP_DIR)
    TEMP_DIR.mkdir()
    exit_notes = list()

    log.info('set hostname and fqdn')
    run_shell_command([
        'hostnamectl',
        'set-hostname',
        args.hostname
    ])
    add_or_replace('127.0.1.1', '127.0.1.1' + ' ' + args.hostname, Path('/etc/hosts').resolve())

    log.info('disable motd ads')
    motd_news = Path('/etc/default/motd-news').resolve()
    if motd_news.is_file():
        add_or_replace('ENABLED=', 'ENABLED=0', motd_news)
    run_shell_command([
        'systemctl',
        'disable',
        '--now',
        'motd-news.timer'
    ])

    log.info('set default apt sources')
    sources_list = Path('/etc/apt/sources.list').resolve()
    write_lines([
        'deb http://archive.ubuntu.com/ubuntu focal main restricted universe multiverse',
        'deb http://archive.ubuntu.com/ubuntu focal-updates main restricted universe multiverse',
        'deb http://archive.ubuntu.com/ubuntu focal-security main restricted universe multiverse',
        'deb http://archive.ubuntu.com/ubuntu focal-backports main restricted universe multiverse'
    ], sources_list)

    log.info('apt update')
    apt_update()

    log.info('set locales')
    apt_install([
        'language-pack-en-base',
        'language-pack-en'
    ])
    run_shell_command([
        'localectl',
        'set-locale',
        args.locale
    ])
    run_shell_command([
        'timedatectl',
        'set-timezone',
        args.timezone
    ])

    log.info('remove bloat')
    apt_purge([
        'apport',
        'apport-symptoms',
        'cloud-guest-utils',
        'cloud-init',
        'cloud-initramfs-copymods',
        'cloud-initramfs-dyn-netconf',
        'landscape-common',
        'pastebinit',
        'popularity-contest',
        'snapd',
        'telnet'
    ])
    run_shell_command(['systemctl', 'daemon-reload'])
    for d in list([Path('/etc/cloud').resolve(),
                   Path('/var/lib/cloud').resolve(),
                   Path('/root/snap').resolve(),
                   Path('/var/cache/snapd').resolve()]):
        delete_path_object(d)

    log.info('upgrade existing apt packages')
    apt_upgrade()

    log.info('installing additional apt packages')
    apt_install([
        'apt-transport-https',
        'apt-utils',
        'bash-completion',
        'ca-certificates',
        'curl',  # used in download_file
        'debconf-utils',
        'fail2ban',
        'git',
        'gnupg-agent',
        'htop',
        'iftop',
        'man',
        'nano',
        'netcat',
        'openssh-server',
        'openssl',
        'rsync',
        'screen',
        'shellcheck',
        'software-properties-common',
        'tldr',
        'tree',
        'ufw',
        'unattended-upgrades',
        'unzip',
        'vim',
        'wget'
    ])

    log.info('add admin user')
    if user_exists(args.username):
        log.warning('user ' + args.username + ' already exists!')
        exit_notes.append('Password for ' + args.username + ' was not changed')
    else:
        # create user
        run_shell_command([
            'adduser',
            '--quiet',
            '--disabled-password',
            '--gecos',
            '',
            args.username,
        ])
        # add to sudo
        run_shell_command([
            'gpasswd',
            '--add',
            args.username,
            'sudo'
        ])
        # generate password
        password = random_string(24)
        run_shell_command(['chpasswd'], pipe_input=args.username + ':' + password)
        # force password change on next login
        run_shell_command([
            'passwd',
            '--expire',
            args.username
        ])
        exit_notes.append('Password for ' + args.username + ' is: ' + password)

    if args.install_postfix is True:
        log.info('installing mail utils')
        # install mailutils and mta
        run_shell_command(['debconf-set-selections'], pipe_input='postfix postfix/mailname string $myhostname')
        run_shell_command(['debconf-set-selections'],
                          pipe_input='postfix postfix/main_mailer_type select Internet Site')
        run_shell_command(['debconf-set-selections'], pipe_input='postfix postfix/protocols select ipv4')
        apt_install(['mailutils', 'postfix'])
        # set postfix config
        write_lines([args.hostname], Path('/etc/mailname').resolve())
        postfix_config = Path('/etc/postfix/main.cf').resolve()
        add_or_replace('myhostname =', 'myhostname = ' + args.hostname, postfix_config)
        add_or_replace('myorigin =', 'myorigin = /etc/mailname', postfix_config)
        add_or_replace('mydestination =', 'mydestination = localhost.$mydomain, localhost, $myhostname', postfix_config)
        add_or_replace('inet_interfaces =', 'inet_interfaces = loopback-only', postfix_config)
        # restart postfix
        run_shell_command(['systemctl', 'restart', 'postfix'])
        # set mail aliases
        aliases = Path('/etc/aliases').resolve()
        add_or_replace('root:', 'root: ' + args.forward_mail, aliases)
        add_or_replace(args.username + ':', args.username + ': ' + args.forward_mail, aliases)
        run_shell_command(['newaliases'])
        # send test mails
        run_shell_command(['mail',
                           '-s',
                           '"beep boop"',
                           'root'], pipe_input='testing mail transfer agent by sending a mail to root')
        run_shell_command(['mail',
                           '-s',
                           '"beep boop"',
                           args.username],
                          pipe_input='testing mail transfer agent by sending a mail to ' + args.username)
        exit_notes.append(
            'Internal server mails of root and ' + args.username + ' are forwarded to: ' + args.forward_mail + '. Please check your inbox for test mails!')

    if args.install_docker is True:
        log.info('installing docker')
        # install gpg key
        download_file('https://download.docker.com/linux/ubuntu/gpg', TEMP_DIR.joinpath('docker_key'))
        run_shell_command([
            'apt-key',
            'add',
            'docker_key'
        ], cwd=TEMP_DIR, env={**os.environ, 'APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE': 'true'})
        # add apt repo
        run_shell_command([
            'add-apt-repository',
            '--yes',
            'deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable'
        ])
        apt_update()
        # install docker
        apt_install([
            'docker-ce',
            'docker-ce-cli',
            'containerd.io'
        ])
        run_shell_command([
            'systemctl',
            'enable',
            'docker'
        ])
        # enable memory limit and swap accounting
        add_or_replace(
            'GRUB_CMDLINE_LINUX=',
            'GRUB_CMDLINE_LINUX="cgroup_enable=memory swapaccount=1"',
            Path('/etc/default/grub').resolve()
        )
        run_shell_command(['update-grub'])
        # install docker-compose
        download_file(
            'https://github.com/docker/compose/releases/download/1.28.0/docker-compose-Linux-x86_64',
            Path('/usr/local/bin/docker-compose').resolve()
        )
        run_shell_command([
            'chmod',
            '+x',
            '/usr/local/bin/docker-compose'
        ])
        exit_notes.append(
            'Docker and docker-compose were installed successfully! read the guide at: https://docs.docker.com/get-started/overview/')

    if args.install_netdata is True:
        log.info('installing netdata')
        download_file(
            'https://my-netdata.io/kickstart.sh',
            TEMP_DIR.joinpath('netdata-install.sh')
        )
        run_shell_command([
            '/usr/bin/env',
            'bash',
            'netdata-install.sh',
            '--non-interactive'
        ], cwd=TEMP_DIR)
        run_shell_command([
            'systemctl',
            'enable',
            'netdata'
        ])
        exit_notes.append(
            'Netdata was installed, establish a connection via ssh tunnel like this: ssh -L 19999:localhost:19999 ' + args.username + '@' + args.hostname + ' and visit http://127.0.0.1:19999/ in your browser. read the guide at: https://github.com/netdata/netdata/blob/master/docs/quickstart/single-node.md')

    log.info('clean up apt packages')
    apt_clean()

    log.info('set kernel network config')
    sysctl_conf = Path('/etc/sysctl.conf').resolve()
    # disable ipv6
    add_or_replace('net.ipv6.conf.all.disable_ipv6=', 'net.ipv6.conf.all.disable_ipv6=1', sysctl_conf)
    add_or_replace('net.ipv6.conf.default.disable_ipv6=', 'net.ipv6.conf.default.disable_ipv6=1', sysctl_conf)
    add_or_replace('net.ipv6.conf.lo.disable_ipv6=', 'net.ipv6.conf.lo.disable_ipv6=1', sysctl_conf)
    if args.harden_network is True:
        add_or_replace('net.ipv4.conf.default.rp_filter=', 'net.ipv4.conf.default.rp_filter=1', sysctl_conf)
        add_or_replace('net.ipv4.conf.all.rp_filter=', 'net.ipv4.conf.all.rp_filter=1', sysctl_conf)
        add_or_replace('net.ipv4.tcp_syncookies=', 'net.ipv4.tcp_syncookies=1', sysctl_conf)
        add_or_replace('net.ipv4.conf.all.accept_redirects=', 'net.ipv4.conf.all.accept_redirects=0', sysctl_conf)
        add_or_replace('net.ipv4.conf.all.send_redirects=', 'net.ipv4.conf.all.send_redirects=0', sysctl_conf)
        add_or_replace('net.ipv4.conf.all.accept_source_route=', 'net.ipv4.conf.all.accept_source_route=0', sysctl_conf)
        add_or_replace('net.ipv4.conf.all.log_martians=', 'net.ipv4.conf.all.log_martians=1', sysctl_conf)
        add_or_replace('net.ipv6.conf.all.accept_redirects=', 'net.ipv6.conf.all.accept_redirects=0', sysctl_conf)
        add_or_replace('net.ipv6.conf.all.accept_source_route=', 'net.ipv6.conf.all.accept_source_route=0', sysctl_conf)
    run_shell_command(['sysctl', '-p'])

    log.info('configure firewall')
    add_or_replace('IPV6=', 'IPV6=no', Path('/etc/ufw/ufw.conf').resolve())
    run_shell_command(['systemctl', 'restart', 'ufw'])
    run_shell_command(['ufw', 'logging', 'on'])
    run_shell_command(['ufw', 'default', 'deny', 'incoming'])
    run_shell_command(['ufw', 'default', 'allow', 'outgoing'])
    run_shell_command(['ufw', 'allow', 'ssh/tcp'])
    run_shell_command(['ufw', '--force', 'enable'])

    log.info('ssh config')
    ssh_config = Path('/etc/ssh/ssh_config').resolve()
    write_lines([
        'HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ssh-rsa,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256',
        'KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256',
        'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com',
        'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr',
        'HashKnownHosts yes'], ssh_config)

    log.info('sshd config')
    sshd_config = Path('/etc/ssh/sshd_config').resolve()
    write_lines(['HostKey /etc/ssh/ssh_host_ed25519_key',
                 'HostKey /etc/ssh/ssh_host_rsa_key',
                 'KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256',
                 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com',
                 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com',
                 'LogLevel VERBOSE',
                 'Subsystem sftp internal-sftp',
                 'PermitRootLogin No',
                 'LoginGraceTime 1m',
                 'UseDNS no',
                 'AllowTcpForwarding no',
                 'X11Forwarding no',
                 'AuthenticationMethods publickey',
                 'UsePAM yes',
                 'PasswordAuthentication no',
                 'PermitEmptyPasswords no',
                 'ChallengeResponseAuthentication no',
                 'KerberosAuthentication no',
                 'GSSAPIAuthentication no',
                 'Match User ' + args.username,
                 '    AllowTcpForwarding yes'
                 ], sshd_config)

    log.info('set admin user ssh key')
    authorized_keys = Path('/home/' + args.username + '/.ssh/authorized_keys').resolve()
    os.makedirs(authorized_keys.parent, exist_ok=True)
    write_lines([args.sshpubkey], authorized_keys)
    run_shell_command(['chmod', '700', str(authorized_keys.parent)])
    run_shell_command(['chmod', '600', str(authorized_keys)])
    run_shell_command(['chown', '-R', args.username + ':' + args.username, authorized_keys.parent])

    log.info('generate sshd server keys')
    ssh_etc = Path('/etc/ssh').resolve()
    host_keys = glob.glob("/etc/ssh/ssh_host_*key*")
    # deleting old ssh server keys
    for key in host_keys:
        run_shell_command(['shred', '-u', key])
    # generating new keys
    run_shell_command(['ssh-keygen', '-t', 'ed25519', '-f', 'ssh_host_ed25519_key', '-N', ''], cwd=ssh_etc)
    run_shell_command(['ssh-keygen', '-t', 'rsa', '-b', '8192', '-f', 'ssh_host_rsa_key', '-N', ''], cwd=ssh_etc)

    log.info('restart sshd')
    run_shell_command(['systemctl', 'restart', 'sshd'])

    delete_path_object(TEMP_DIR)

    exit_notes.append('Please reboot the machine for certain changes to take effect!')

    print('--------')
    for line in exit_notes:
        print(line)
        print('--------')
