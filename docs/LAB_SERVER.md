# Lab SSH server (operator-owned)

Use a VPS you control. Do **not** use random free SSH lists.

## Minimal OpenSSH on port 443

```bash
# Ubuntu example
sudo apt update && sudo apt install -y openssh-server
sudo mkdir -p /etc/ssh/sshd_config.d
echo 'Port 443
PasswordAuthentication yes
PubkeyAuthentication yes
AllowTcpForwarding yes
PermitTunnel no
' | sudo tee /etc/ssh/sshd_config.d/netpath-lab.conf
sudo systemctl restart ssh
```

Create a dedicated lab user with a strong password or key-only auth.

```bash
sudo adduser netpath
sudo ufw allow 443/tcp
```

## App settings

- **SSH server host / IP:** your VPS public IP
- **Port:** `443` (or `22` for Direct tests)
- **Username / password or PEM**
- For SNI mismatch: **Custom SNI** = a hostname your pack product might recognize (for training), while host field stays the VPS IP

## Optional later: stunnel

For scenario `TLS_FULL_SNI`, terminate TLS on the VPS (stunnel/sslh) and forward to sshd. ClientHello-only mode does **not** need stunnel.

## Safety

- Restrict SSH to your SOC source IPs when possible.
- Rotate lab credentials after exercises.
- Monitor auth logs during drills (`/var/log/auth.log`).
