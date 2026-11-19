```
kill 000
```
(returns root credentials to the calling process)

## Build on the web server (172.16.10.111)

```bash
# as root, headers must match the running kernel (6.12.113 held)
apt-get install -y linux-headers-$(uname -r) build-essential
cd /path/to/blacklodge_lkm/kernelspace
make
insmod blacklodge_lkm.ko
```

After `insmod` the module disappears from `lsmod` / `/proc/modules`.

## Persistence (lab)

The original bds install script drops a systemd unit that reloads the module after boot.  
For the lab you can either:

1. Keep the original persistence mechanism, or
2. Simply document that Jack ran `insmod` and left a oneshot service / rc.local entry (students find the evidence in `~jack/.bash_history`).

## Layout script coordination

Update `web_3b_layout.sh` so that every artifact that should be hidden uses the new prefix:

- `/var/www/html/blacklodge_data/`
- `/usr/local/sbin/blacklodge_beacon` (and the process name set via prctl)
- systemd unit name can stay bland or also use the prefix

The beacon must still listen on 1337 so the port-hide logic continues to work.

## Student hunting checklist (suggested)

- External nmap sees 1337 open; on-box `ss -tlnp` does not.
- `ls /var/www/html` does not show the data directory; absolute path still works.
- `lsmod` does not list the module; `cat /proc/modules` also clean.
- `~jack/.bash_history` still contains the make/insmod evidence.
- `kill 000` works as a quick confirmation of the priv-esc hook.

## Objective Four note

A minimal student skeleton (single getdents hook + clean unload) will be produced separately once this full implant is verified on the 6.12.113 image.
