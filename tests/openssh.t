Authenticate user, create key, download certificate, refresh known hosts and krl file if needed, store keys in ssh-agent, write public keys in identity file and certificate file
  $ pf openssh auth --host device.name --known-hosts ./user_ca_cert_known_hosts --host-krl ./host.krl --identity-file ./device.name.pub --certificate-file ./device.name.cert
