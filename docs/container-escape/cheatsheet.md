# Container Escape — Pentest Cheat Sheet

## 1. cgroup release_agent (User-Mode Helper)

**Attack chain**
1. Find writable cgroup mount
2. mkdir new cgroup
3. `echo 1 > notify_on_release`
4. `echo <payload_path> > release_agent`
5. `echo 0 > cgroup.procs` (triggers agent)

**Prerequisites**
- Root in container
- cgroup v1/v2 writable mounts
- No `no_new_privs` or seccomp blocking file writes

**Detection**
- Monitor `call_usermodehelper()` events
- Watch for writes to `release_agent`
- EDR/XDR alert chain (process tree anomaly)

**Mitigations**
- Drop all capabilities
- Read-only cgroup mounts
- Seccomp blocking `open/write` on cgroup paths
- Use `no_new_privs: true`

---

## 2. SUID on Host-Shared File

**Attack chain**
1. Identify shared directory between container and host
2. Write executable file in shared dir
3. `chmod u+s file`
4. Execute file from host

**Prerequisites**
- Root inside container
- Shared volume with host
- Host user with permission to run SUID binaries

**Detection**
- File creation in shared mounts
- `chmod` adding SUID bit
- Execution of SUID file from host by non-root user

**Mitigations**
- Do not mount host directories into containers
- Use `nosuid` mount option
- Restrict container root access

---

## 3. Runtime Socket Mount

**Attack chain**
1. Check `/var/run/docker.sock` inside container
2. `curl --unix-socket /var/run/docker.sock http://localhost/containers/json`
3. Create privileged container with host mount

**Example curl**
```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["cat","/etc/shadow"],"Binds":["/:/host"],"Privileged":true}' \
  http://localhost/containers/create
curl --unix-socket /var/run/docker.sock \
  http://localhost/containers/<id>/start
```

**Prerequisites**
- `/var/run/docker.sock` mounted in container
- Container runtime socket accessible

**Detection**
- Unix socket access from container context
- `docker run` / containerd commands from container
- Anomalous container creation

**Mitigations**
- Never mount runtime sockets
- Use rootless containers
- Enable authentication on Docker API
- Network segmentation

---

## 4. Log Mount / Pod Escape (Kubernetes)

**Attack chain**
1. Pod with `/var/log` mounted from host
2. `ln -sf / /var/log/root_host`
3. `kubectl logs <pod> --previous` or API POST
4. Read `/var/log/root_host/etc/passwd`

**Prerequisites**
- Kubernetes pod
- `/var/log` host path mounted
- `kubectl`/service account with log read access

**Detection**
- HTTP requests to K8s API for log reads with suspicious paths
- Symlink creation/modification in `/var/log`
- Container writing to host `/var/log`

**Mitigations**
- Do not mount host `/var/log` into pods
- Read-only root filesystem
- Restrict kubectl/service account log access
- Kubelet symlink validation patches

---

## 5. Sensitive Mount

**Attack chain**
1. Identify host-mounted sensitive paths (`/etc`, `/proc`, `/sys`)
2. Read/write through container view of host filesystem

**Prerequisites**
- Misconfigured `volumes` / bind mounts
- Host path exposed in container

**Detection**
- Monitor file access on sensitive host paths
- Convert container path → host path for accurate alerting
- Alert on reads of `/etc/shadow`, `/etc/passwd`

**Mitigations**
- No host bind mounts unless absolutely required
- `readOnly` root filesystem
- AppArmor/SELinux policies
- Prisma Cloud Defender / Cortex XDR path translation

---

## Defensive Baseline

```
Capabilities: drop ALL by default, add back only what is needed
Namespaces: PID, NET, IPC, USER, UTS, CGROUP enabled
Seccomp: whitelist syscalls
Read-only root: true
No_new_privs: true
No host mounts unless required
No runtime socket mounts
```
