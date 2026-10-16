# Docker's default seccomp profile plus an unconditional ALLOW for the syscalls bubblewrap needs to make a box's namespaces and
# mounts without any capability: the runner container's profile (compose.yaml). Regenerate it for the Docker version on the host
# (`docker version --format '{{.Server.Version}}'`); all five are needed, a box does not start without any one of them:
#   curl -fsSL -o default.json https://raw.githubusercontent.com/moby/moby/v<version>/profiles/seccomp/default.json
#   python3 -I mkprofile.py default.json seccomp-bwrap.json unshare clone mount umount2 pivot_root
import json, sys
p = json.load(open(sys.argv[1]))
p["syscalls"].append({"names": sys.argv[3:], "action": "SCMP_ACT_ALLOW"})
json.dump(p, open(sys.argv[2], "w"), indent=1)
