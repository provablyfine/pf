FROM fedora:latest

RUN dnf install -y python3 uv openssh-clients systemd && dnf clean all

COPY pyproject.toml /tmp/pf/
COPY src /tmp/pf/src/
RUN uv pip install --system --break-system-packages /tmp/pf && rm -rf /tmp/pf

RUN mkdir -p /usr/lib/systemd/system /usr/lib/pf/scripts /var/lib/pf /run/pf

COPY podman/units/pf-host-init.socket /usr/lib/systemd/system/
COPY podman/units/pf-host-init.service /usr/lib/systemd/system/
COPY podman/units/pf-host-refresh.service /usr/lib/systemd/system/
COPY podman/units/pf-host-refresh.timer /usr/lib/systemd/system/
COPY podman/units/pf-host-bastion.service /usr/lib/systemd/system/
COPY --chmod=755 podman/scripts/detect-sshd-port.sh /usr/lib/pf/scripts/
