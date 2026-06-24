# Container Escape — Quick Reference Table

| Technique | Attack Vector | Requires | Detectable | Severity | Mitigation |
|---|---|---|---|---|---|
| release_agent | Write cgroup `release_agent` and empty group | Root, writable cgroup | `call_usermodehelper`, FIM on cgroup files | Critical | Drop capabilities, read-only cgroup mounts, seccomp |
| SUID shared file | `chmod u+s` on file in host-shared volume | Shared volume, same user namespace | File creation, SUID addition, host execution | High | Avoid host mounts, `nosuid` mount option |
| Runtime socket | Use mounted Docker/containerd socket to spawn privileged container | Socket mounted inside container | Socket access, new container creation from inside container | Critical | Do not mount runtime sockets, network segmentation |
| Log mount (K8s) | Symlink `/var/log` entry to read arbitrary host files via kubectl logs | `/var/log` host mount, log read access | K8s API log reads with abnormal paths, host-side symlink creation | High | Remove host `/var/log` mounts, restrict kubectl log access |
| Sensitive mount | Read/write host files via bind-mounted sensitive paths | Misconfigured host bind mounts | FIM on sensitive host paths, container→host path correlation | Medium to High | No host bind mounts, read-only root, security policies |

---

## Enumeration Commands

```bash
# Capabilities
capsh --print

# Mounts
mount
cat /proc/self/mountinfo

# Cgroup
find /sys/fs/cgroup -writable -type d 2>/dev/null
cat /proc/self/cgroup

# Runtime sockets
ls -l /var/run/docker.sock /run/containerd/containerd.sock

# Shared volumes
cat /proc/self/mountinfo | grep -E 'docker|kubelet|host'

# Kubernetes
kubectl get pods -o yaml | grep -i 'mount'
curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

---

## Severity Mapping

- **Critical:** root on host with minimal steps (release_agent, runtime socket)
- **High:** significant host access or host logic abuse (SUID, log mount)
- **Medium:** requires both misconfig + weak isolation (sensitive mounts)

---

*Use this table during pentest scoping and reporting.*
