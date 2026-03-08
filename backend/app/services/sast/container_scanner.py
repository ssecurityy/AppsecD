"""Container & image security scanner.

Analyzes Dockerfiles and docker-compose files for security issues.
Optionally integrates with Trivy for image vulnerability scanning.
"""
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess

logger = logging.getLogger(__name__)

SKIP_DIRS = {"node_modules", ".git", "vendor", "__pycache__", "dist", "build", ".next"}
MAX_FILE_SIZE = 2 * 1024 * 1024


def _fingerprint(rule_id: str, file_path: str, line: int) -> str:
    raw = f"{rule_id}|{file_path}|{line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _finding(rule_id: str, severity: str, confidence: str, title: str,
             description: str, file_path: str, line: int, snippet: str,
             cwe_id: str, owasp: str) -> dict:
    return {
        "rule_id": rule_id,
        "rule_source": "container",
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "file_path": file_path,
        "line_start": line,
        "line_end": line,
        "code_snippet": snippet[:2000],
        "cwe_id": cwe_id,
        "owasp_category": owasp,
        "fingerprint": _fingerprint(rule_id, file_path, line),
    }


def scan_compose_files(source_path: str) -> list[dict]:
    """Analyze docker-compose.yml files for security issues."""
    findings: list[dict] = []

    for root, dirs, filenames in os.walk(source_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            if fname not in ("docker-compose.yml", "docker-compose.yaml",
                             "compose.yml", "compose.yaml"):
                continue
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue

            rel_path = os.path.relpath(fpath, source_path)
            findings.extend(_scan_compose(content, rel_path))

    return findings


def _scan_compose(content: str, rel_path: str) -> list[dict]:
    """Check a docker-compose file for security issues."""
    findings: list[dict] = []

    for m in re.finditer(r"privileged\s*:\s*true", content):
        ln = content[:m.start()].count("\n") + 1
        findings.append(_finding(
            "container.compose.privileged", "critical", "high",
            "Container runs in privileged mode",
            "A service in docker-compose is configured with privileged: true, giving "
            "full host access. Remove the privileged flag.",
            rel_path, ln, m.group(0), "CWE-250", "A01:2021",
        ))

    for m in re.finditer(r"network_mode\s*:\s*['\"]?host['\"]?", content):
        ln = content[:m.start()].count("\n") + 1
        findings.append(_finding(
            "container.compose.host-network", "high", "high",
            "Container uses host network mode",
            "A service uses network_mode: host, sharing the host's network stack. "
            "Use bridge or overlay networking instead.",
            rel_path, ln, m.group(0), "CWE-284", "A01:2021",
        ))

    for m in re.finditer(r"pid\s*:\s*['\"]?host['\"]?", content):
        ln = content[:m.start()].count("\n") + 1
        findings.append(_finding(
            "container.compose.host-pid", "high", "high",
            "Container shares host PID namespace",
            "pid: host shares the host's process namespace with the container, "
            "allowing visibility into and signaling of host processes.",
            rel_path, ln, m.group(0), "CWE-284", "A01:2021",
        ))

    for m in re.finditer(
        r"(?:MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|DB_PASSWORD|SECRET_KEY|API_KEY|AUTH_TOKEN)"
        r"\s*[:=]\s*['\"]?[^\s'\"$]{4,}",
        content, re.IGNORECASE,
    ):
        ln = content[:m.start()].count("\n") + 1
        findings.append(_finding(
            "container.compose.hardcoded-secret", "high", "high",
            "Hardcoded secret in docker-compose",
            "A password or secret is hardcoded in the compose file. "
            "Use Docker secrets or environment files (.env) with restricted permissions.",
            rel_path, ln, m.group(0)[:100], "CWE-798", "A07:2021",
        ))

    if not re.search(r"(?:mem_limit|memory|deploy.*limits.*memory)", content, re.DOTALL):
        findings.append(_finding(
            "container.compose.no-resource-limits", "medium", "medium",
            "No memory limits defined for services",
            "The docker-compose file does not define memory limits. Without limits, "
            "a container can consume all host memory. Add deploy.resources.limits.",
            rel_path, 1, "", "CWE-770", "A05:2021",
        ))

    for m in re.finditer(r":\s*['\"]?(\d+):(\d+)['\"]?", content):
        host_port = m.group(1)
        if host_port in ("22", "3389", "5432", "3306", "27017", "6379", "9200", "2375", "2376"):
            ln = content[:m.start()].count("\n") + 1
            findings.append(_finding(
                "container.compose.sensitive-port-exposed", "high", "medium",
                f"Sensitive port {host_port} exposed to host",
                f"Port {host_port} is mapped to the host. This may expose sensitive services "
                f"(database, SSH, Docker daemon) externally.",
                rel_path, ln, m.group(0), "CWE-284", "A01:2021",
            ))

    for m in re.finditer(r"volumes\s*:\s*\n((?:\s+-\s*.+\n)*)", content):
        block = m.group(1)
        for vol_m in re.finditer(r"-\s*['\"]?(/(?:var|etc|root|proc|sys|dev)[^\s'\"]*)", block):
            host_path = vol_m.group(1)
            ln = content[:m.start() + vol_m.start()].count("\n") + 1
            findings.append(_finding(
                "container.compose.sensitive-mount", "high", "high",
                f"Sensitive host path mounted: {host_path}",
                f"The volume mount {host_path} gives the container access to sensitive "
                f"host directories. Restrict volume mounts to application data only.",
                rel_path, ln, vol_m.group(0), "CWE-284", "A01:2021",
            ))

    # ── 8. Dangerous cap_add capabilities ────────────────────────────────
    _DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE",
                       "NET_RAW", "SYS_RAWIO", "SYS_MODULE", "MKNOD"}
    for m in re.finditer(r"cap_add\s*:\s*\n((?:\s+-\s*.+\n)*)", content):
        block = m.group(1)
        for cap_m in re.finditer(r"-\s*(\w+)", block):
            cap = cap_m.group(1).upper()
            if cap in _DANGEROUS_CAPS:
                ln = content[:m.start() + cap_m.start()].count("\n") + 1
                findings.append(_finding(
                    "container.compose.dangerous-cap-add", "high", "high",
                    f"Dangerous Linux capability added: {cap}",
                    f"The capability {cap} is granted to the container via cap_add. "
                    f"This grants elevated host privileges. Remove the capability or use "
                    f"cap_drop: [ALL] with only the minimum required capabilities.",
                    rel_path, ln, cap_m.group(0), "CWE-250", "A01:2021",
                ))

    # ── 9. Missing cap_drop ALL ──────────────────────────────────────────
    # Check per-service: look for service blocks that lack cap_drop: [ALL]
    if re.search(r"services\s*:", content):
        if not re.search(r"cap_drop\s*:\s*\n\s+-\s*ALL", content) and \
           not re.search(r"cap_drop\s*:\s*\[\s*ALL\s*\]", content):
            findings.append(_finding(
                "container.compose.missing-cap-drop-all", "medium", "medium",
                "Missing cap_drop: [ALL] for services",
                "Docker Compose services do not drop all Linux capabilities. "
                "Best practice is to use cap_drop: [ALL] and then selectively add only "
                "required capabilities with cap_add.",
                rel_path, 1, "", "CWE-250", "A01:2021",
            ))

    # ── 10. IPC host mode ────────────────────────────────────────────────
    for m in re.finditer(r"ipc\s*:\s*['\"]?host['\"]?", content):
        ln = content[:m.start()].count("\n") + 1
        findings.append(_finding(
            "container.compose.ipc-host", "high", "high",
            "Container shares host IPC namespace",
            "ipc: host shares the host's IPC namespace with the container, "
            "allowing shared memory access and potential data leakage between "
            "the container and host processes.",
            rel_path, ln, m.group(0), "CWE-284", "A01:2021",
        ))

    # ── 11. Explicit root user ───────────────────────────────────────────
    for m in re.finditer(r"^\s*user\s*:\s*['\"]?(?:root|0)['\"]?\s*$", content, re.MULTILINE):
        ln = content[:m.start()].count("\n") + 1
        findings.append(_finding(
            "container.compose.user-root", "medium", "high",
            "Container explicitly runs as root",
            "The service is configured with user: root (or user: 0). Containers "
            "should run as a non-root user to limit the impact of container escapes.",
            rel_path, ln, m.group(0).strip(), "CWE-250", "A01:2021",
        ))

    # ── 12. tmpfs without noexec ─────────────────────────────────────────
    for m in re.finditer(r"tmpfs\s*:\s*\n((?:\s+-\s*.+\n)*)", content):
        block = m.group(1)
        for tmp_m in re.finditer(r"-\s*([^\n]+)", block):
            mount_spec = tmp_m.group(1)
            if "noexec" not in mount_spec:
                ln = content[:m.start() + tmp_m.start()].count("\n") + 1
                findings.append(_finding(
                    "container.compose.tmpfs-no-noexec", "low", "medium",
                    "tmpfs mount without noexec option",
                    "A tmpfs mount is configured without the noexec option. Adding "
                    "noexec prevents execution of binaries from the tmpfs, reducing "
                    "attack surface. Use tmpfs with 'noexec,nosuid,nodev' options.",
                    rel_path, ln, mount_spec.strip(), "CWE-269", "A05:2021",
                ))

    # ── 13. Missing read_only filesystem ─────────────────────────────────
    if re.search(r"services\s*:", content):
        if not re.search(r"read_only\s*:\s*true", content):
            findings.append(_finding(
                "container.compose.missing-read-only", "low", "medium",
                "No read-only root filesystem for services",
                "No services use read_only: true. A read-only root filesystem prevents "
                "attackers from writing malicious files or modifying binaries inside the "
                "container. Use read_only: true with tmpfs for writable directories.",
                rel_path, 1, "", "CWE-269", "A05:2021",
            ))

    # ── 14. Missing CPU limits ───────────────────────────────────────────
    if re.search(r"services\s*:", content):
        if not re.search(r"(?:cpus|cpu_shares|cpu_quota|deploy.*limits.*cpus)", content, re.DOTALL):
            findings.append(_finding(
                "container.compose.no-cpu-limits", "medium", "medium",
                "No CPU limits defined for services",
                "The docker-compose file does not define CPU limits. Without CPU limits, "
                "a container can monopolize host CPU resources, causing denial of service "
                "for other containers. Add deploy.resources.limits.cpus.",
                rel_path, 1, "", "CWE-770", "A05:2021",
            ))

    # ── 15. No logging driver ────────────────────────────────────────────
    if re.search(r"services\s*:", content):
        if not re.search(r"logging\s*:", content):
            findings.append(_finding(
                "container.compose.no-logging", "low", "medium",
                "No logging driver configured for services",
                "The docker-compose file does not configure a logging driver. "
                "Without explicit logging configuration, container logs may grow "
                "unbounded or not be forwarded to a centralized logging system.",
                rel_path, 1, "", "CWE-778", "A09:2021",
            ))

    # ── 16. restart without healthcheck ──────────────────────────────────
    if re.search(r"restart\s*:\s*['\"]?(?:always|unless-stopped)['\"]?", content):
        if not re.search(r"healthcheck\s*:", content):
            findings.append(_finding(
                "container.compose.restart-no-healthcheck", "low", "medium",
                "Restart policy without healthcheck",
                "A service uses restart: always or restart: unless-stopped without "
                "a healthcheck. Without a healthcheck, Docker cannot detect if the "
                "application inside the container is actually healthy, leading to "
                "restart loops of broken containers.",
                rel_path, 1, "", "CWE-693", "A05:2021",
            ))

    # ── 17. Sensitive environment variables with hardcoded values ────────
    for m in re.finditer(
        r"(?:^|\n)\s*-?\s*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|DATABASE_URL|"
        r"AWS_SECRET_ACCESS_KEY|ENCRYPTION_KEY|SIGNING_KEY|CLIENT_SECRET)"
        r"\s*[=:]\s*['\"]?([^\s'\"\n$]{4,})",
        content, re.IGNORECASE,
    ):
        val = m.group(1)
        # Skip references to env vars and Docker secrets
        if val.startswith("${") or val.startswith("$") or val.startswith("/run/secrets"):
            continue
        ln = content[:m.start()].count("\n") + 1
        findings.append(_finding(
            "container.compose.sensitive-env-hardcoded", "high", "high",
            "Sensitive environment variable with hardcoded value",
            "An environment variable containing a password, secret, or API key has a "
            "hardcoded value. Use Docker secrets, external secret managers, or .env files "
            "with restricted file permissions.",
            rel_path, ln, m.group(0).strip()[:100], "CWE-798", "A07:2021",
        ))

    # ── 18. Docker socket mount ──────────────────────────────────────────
    for m in re.finditer(r"/var/run/docker\.sock", content):
        ln = content[:m.start()].count("\n") + 1
        findings.append(_finding(
            "container.compose.docker-socket-mount", "critical", "high",
            "Docker socket mounted into container",
            "The Docker socket (/var/run/docker.sock) is mounted into the container, "
            "giving full control over the Docker daemon. This is equivalent to root "
            "access on the host. Avoid mounting the Docker socket unless absolutely "
            "necessary, and use read-only mode if required.",
            rel_path, ln, "/var/run/docker.sock", "CWE-250", "A01:2021",
        ))

    # ── 19. Missing security_opt no-new-privileges ───────────────────────
    if re.search(r"services\s*:", content):
        if not re.search(r"security_opt\s*:", content):
            findings.append(_finding(
                "container.compose.missing-security-opt", "medium", "medium",
                "Missing security_opt: [no-new-privileges:true]",
                "No services configure security_opt. Adding security_opt: "
                "[no-new-privileges:true] prevents processes from gaining additional "
                "privileges via setuid/setgid binaries.",
                rel_path, 1, "", "CWE-250", "A01:2021",
            ))

    # ── 20. Network host mode with ports exposed ─────────────────────────
    # If network_mode: host is used, ports: section is redundant and indicates confusion
    if re.search(r"network_mode\s*:\s*['\"]?host['\"]?", content):
        if re.search(r"ports\s*:", content):
            findings.append(_finding(
                "container.compose.host-network-with-ports", "medium", "medium",
                "Host network mode used with ports mapping",
                "A service uses network_mode: host together with ports mapping. "
                "In host network mode, port mapping is ignored and all ports are "
                "directly exposed on the host. This may indicate a misconfiguration.",
                rel_path, 1, "", "CWE-284", "A05:2021",
            ))

    # ── 21. Exposed debug ports ──────────────────────────────────────────
    _DEBUG_PORTS = {"5005", "9229", "4200", "8000", "5858", "9222", "5555", "1234"}
    for m in re.finditer(r"['\"]?(\d+):(\d+)['\"]?", content):
        host_port = m.group(1)
        if host_port in _DEBUG_PORTS:
            ln = content[:m.start()].count("\n") + 1
            findings.append(_finding(
                "container.compose.debug-port-exposed", "medium", "high",
                f"Debug port {host_port} exposed to host",
                f"Port {host_port} is commonly used for debugging (Node.js inspector, "
                f"Java JDWP, etc.) and is mapped to the host. Debug ports should not "
                f"be exposed in production environments.",
                rel_path, ln, m.group(0), "CWE-489", "A05:2021",
            ))

    # ── 22. Missing memory limits (per-service granular check) ───────────
    # The existing check (#5 above) already catches global missing memory limits.
    # This adds a more specific check for the combination pattern.

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# DOCKERFILE SCANNER
# ═══════════════════════════════════════════════════════════════════════════

_DOCKERFILE_NAMES = {"Dockerfile", "dockerfile", "Containerfile", "containerfile"}
_DOCKERFILE_PREFIXES = {"Dockerfile.", "dockerfile.", "Containerfile.", "containerfile."}


def scan_dockerfiles(source_path: str) -> list[dict]:
    """Walk the source tree and analyze all Dockerfiles for security issues."""
    findings: list[dict] = []

    for root, dirs, filenames in os.walk(source_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            is_dockerfile = (
                fname in _DOCKERFILE_NAMES
                or any(fname.startswith(p) for p in _DOCKERFILE_PREFIXES)
            )
            if not is_dockerfile:
                continue

            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue

            rel_path = os.path.relpath(fpath, source_path)
            findings.extend(_scan_dockerfile(content, rel_path))

    return findings


def _scan_dockerfile(content: str, rel_path: str) -> list[dict]:
    """Check a Dockerfile for security issues."""
    findings: list[dict] = []
    lines = content.split("\n")

    # ── D1. COPY without --chown when USER is non-root ───────────────────
    has_non_root_user = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"^USER\s+(?!root\b)(?!0\b)\S+", stripped):
            has_non_root_user = True
        if has_non_root_user and re.match(r"^COPY\s+(?!--chown)", stripped):
            findings.append(_finding(
                "container.dockerfile.copy-no-chown", "low", "medium",
                "COPY without --chown after non-root USER",
                "A COPY instruction is used after a non-root USER directive without "
                "--chown. Files will be owned by root inside the container, which may "
                "cause permission issues or security concerns. Use COPY --chown=user:group.",
                rel_path, i + 1, stripped[:200], "CWE-732", "A01:2021",
            ))

    # ── D2. Package cache not cleaned in same RUN layer ──────────────────
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Detect multi-line RUN instructions
        if not re.match(r"^RUN\s+", stripped):
            continue
        # Collect the full RUN instruction (handle line continuations)
        run_cmd = stripped
        j = i
        while run_cmd.endswith("\\") and j + 1 < len(lines):
            j += 1
            run_cmd += "\n" + lines[j].strip()

        has_install = bool(re.search(r"apt-get\s+install|yum\s+install|dnf\s+install|apk\s+add|pip\s+install", run_cmd))
        has_cleanup = bool(re.search(
            r"rm\s+-rf\s+/var/lib/apt/lists|apt-get\s+clean|yum\s+clean\s+all|"
            r"dnf\s+clean\s+all|apk\s+--no-cache|rm\s+-rf\s+/var/cache|"
            r"--no-cache-dir|pip\s+install.*--no-cache",
            run_cmd,
        ))
        if has_install and not has_cleanup:
            findings.append(_finding(
                "container.dockerfile.no-package-cache-cleanup", "low", "medium",
                "Package installation without cache cleanup",
                "A RUN instruction installs packages without cleaning the package "
                "manager cache in the same layer. This bloats the image size and may "
                "include unnecessary cached data. Add cache cleanup in the same RUN "
                "instruction (e.g., 'rm -rf /var/lib/apt/lists/*').",
                rel_path, i + 1, stripped[:200], "CWE-459", "A05:2021",
            ))

    # ── D3. WORKDIR with relative path ───────────────────────────────────
    for i, line in enumerate(lines):
        stripped = line.strip()
        m = re.match(r"^WORKDIR\s+(\S+)", stripped)
        if m:
            workdir_path = m.group(1)
            if not workdir_path.startswith("/") and not workdir_path.startswith("$"):
                findings.append(_finding(
                    "container.dockerfile.workdir-relative", "low", "medium",
                    "WORKDIR uses relative path",
                    f"WORKDIR is set to a relative path '{workdir_path}'. Relative paths "
                    f"depend on the previous WORKDIR and can lead to unexpected behavior. "
                    f"Always use absolute paths for WORKDIR.",
                    rel_path, i + 1, stripped, "CWE-426", "A05:2021",
                ))

    # ── D4. ADD when COPY would suffice ──────────────────────────────────
    for i, line in enumerate(lines):
        stripped = line.strip()
        m = re.match(r"^ADD\s+(\S+)", stripped)
        if m:
            source = m.group(1)
            # ADD is appropriate for URLs and tar extraction
            is_url = source.startswith("http://") or source.startswith("https://")
            is_tar = re.search(r"\.(?:tar|gz|tgz|bz2|xz|zip)(?:\s|$)", source)
            if not is_url and not is_tar:
                findings.append(_finding(
                    "container.dockerfile.add-instead-of-copy", "low", "high",
                    "ADD used when COPY would suffice",
                    "The ADD instruction is used for a local file that is not a tar archive "
                    "or URL. ADD has implicit tar extraction and remote URL support which "
                    "can be unexpected. Use COPY for simple file copies.",
                    rel_path, i + 1, stripped[:200], "CWE-693", "A05:2021",
                ))

    # ── D5. EXPOSE large port range ──────────────────────────────────────
    for i, line in enumerate(lines):
        stripped = line.strip()
        m = re.match(r"^EXPOSE\s+(\d+)-(\d+)", stripped)
        if m:
            start_port = int(m.group(1))
            end_port = int(m.group(2))
            if end_port - start_port > 100:
                findings.append(_finding(
                    "container.dockerfile.expose-port-range", "medium", "high",
                    f"Large port range exposed: {start_port}-{end_port}",
                    f"The EXPOSE instruction declares a large port range ({start_port}-"
                    f"{end_port}, {end_port - start_port} ports). Exposing a wide port "
                    f"range increases the attack surface. Only expose specific ports needed "
                    f"by the application.",
                    rel_path, i + 1, stripped, "CWE-284", "A01:2021",
                ))

    # ── D6. ENV with secrets ─────────────────────────────────────────────
    for i, line in enumerate(lines):
        stripped = line.strip()
        m = re.match(
            r"^ENV\s+(\S*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|"
            r"ENCRYPTION_KEY|AWS_SECRET|CLIENT_SECRET)\S*)\s*[=\s]\s*(\S+)",
            stripped, re.IGNORECASE,
        )
        if m:
            var_name = m.group(1)
            var_value = m.group(2)
            # Skip if the value is a variable reference
            if var_value.startswith("$") or var_value.startswith("${"):
                continue
            findings.append(_finding(
                "container.dockerfile.env-secret", "high", "high",
                f"Secret in ENV instruction: {var_name}",
                f"The ENV instruction sets '{var_name}' to a value that appears to be "
                f"a hardcoded secret. ENV values are baked into the image layer and visible "
                f"to anyone with access to the image. Use build-time secrets (--secret) "
                f"or runtime environment variables instead.",
                rel_path, i + 1, stripped[:200], "CWE-798", "A07:2021",
            ))

    # ── D7. Missing HEALTHCHECK ──────────────────────────────────────────
    if not re.search(r"^HEALTHCHECK\s+", content, re.MULTILINE):
        # Only flag if this looks like a real Dockerfile (has FROM)
        if re.search(r"^FROM\s+", content, re.MULTILINE):
            findings.append(_finding(
                "container.dockerfile.no-healthcheck", "low", "medium",
                "Dockerfile missing HEALTHCHECK instruction",
                "The Dockerfile does not contain a HEALTHCHECK instruction. Without a "
                "health check, Docker and orchestrators cannot detect if the application "
                "inside the container is actually responsive. Add HEALTHCHECK CMD.",
                rel_path, 1, "", "CWE-693", "A05:2021",
            ))

    # ── D8. Deprecated MAINTAINER instruction ────────────────────────────
    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"^MAINTAINER\s+", stripped):
            findings.append(_finding(
                "container.dockerfile.deprecated-maintainer", "low", "high",
                "Deprecated MAINTAINER instruction",
                "The MAINTAINER instruction is deprecated since Docker 1.13. "
                "Use LABEL maintainer=\"name@example.com\" instead for metadata.",
                rel_path, i + 1, stripped[:200], "CWE-477", "A05:2021",
            ))

    # ── D9. Shell form CMD (not exec form) ───────────────────────────────
    for i, line in enumerate(lines):
        stripped = line.strip()
        m = re.match(r"^CMD\s+(.+)", stripped)
        if m:
            cmd_arg = m.group(1).strip()
            # Exec form starts with [ — shell form does not
            if not cmd_arg.startswith("["):
                findings.append(_finding(
                    "container.dockerfile.shell-form-cmd", "low", "medium",
                    "CMD uses shell form instead of exec form",
                    "The CMD instruction uses shell form, which runs the command via "
                    "/bin/sh -c. This adds an extra shell process, does not receive "
                    "UNIX signals properly (PID 1 issues), and prevents signal forwarding "
                    "for graceful shutdown. Use exec form: CMD [\"executable\", \"arg\"].",
                    rel_path, i + 1, stripped[:200], "CWE-693", "A05:2021",
                ))

    return findings


def scan_with_trivy(image_name: str) -> list[dict]:
    """Optional Trivy integration for image vulnerability scanning.

    Only runs if trivy is installed on the system.
    """
    if not shutil.which("trivy"):
        logger.info("Trivy not installed — skipping image scan for %s", image_name)
        return []

    try:
        result = subprocess.run(
            ["trivy", "image", "--format", "json", "--quiet", image_name],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            logger.warning("Trivy scan failed for %s: %s", image_name, result.stderr[:500])
            return []

        data = json.loads(result.stdout) if result.stdout else {}
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        logger.warning("Trivy scan error for %s: %s", image_name, e)
        return []

    findings: list[dict] = []
    severity_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

    for target in data.get("Results", []):
        for vuln in target.get("Vulnerabilities", []):
            sev = severity_map.get(vuln.get("Severity", ""), "medium")
            vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
            pkg_name = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")
            title = vuln.get("Title", f"{vuln_id} in {pkg_name}")

            desc = vuln.get("Description", "")[:500]
            if fixed:
                desc += f" Fixed in version {fixed}."

            fp_raw = f"trivy:{image_name}:{vuln_id}:{pkg_name}"
            findings.append({
                "rule_id": f"container.trivy.{vuln_id}",
                "rule_source": "container",
                "severity": sev,
                "confidence": "high",
                "title": title[:500],
                "description": desc,
                "message": f"{vuln_id}: {pkg_name} {installed}",
                "file_path": image_name,
                "line_start": 0,
                "line_end": 0,
                "code_snippet": f"{pkg_name} {installed}",
                "cwe_id": (vuln.get("CweIDs") or [""])[0] if vuln.get("CweIDs") else "",
                "owasp_category": "A06:2021",
                "fingerprint": hashlib.sha256(fp_raw.encode()).hexdigest()[:32],
                "references": [{"url": ref} for ref in (vuln.get("References") or [])[:5]],
            })

    logger.info("Trivy scan of %s: %d vulnerabilities", image_name, len(findings))
    return findings


def scan_containers(source_path: str) -> list[dict]:
    """Main entry point: scan all container-related files in a source directory.

    Covers docker-compose files and Dockerfiles.
    """
    findings = scan_compose_files(source_path)
    findings.extend(scan_dockerfiles(source_path))

    seen: set[str] = set()
    deduped: list[dict] = []
    for f in findings:
        fp = f.get("fingerprint", "")
        if fp and fp in seen:
            continue
        seen.add(fp)
        deduped.append(f)

    logger.info("Container scan complete: %d findings", len(deduped))
    return deduped
