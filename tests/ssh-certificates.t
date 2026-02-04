Generate private key
  $ ssh-keygen -t ed25519 -f account -N "" > /dev/null

Generate self-signed certificate
  $ ssh-keygen -s account -I hello -h account.pub
  Signed host key account-cert.pub: id "hello" serial 0 valid forever\r (esc)

Read it back
  $ ssh-keygen -L -f ./account-cert.pub
  ./account-cert.pub:
          Type: ssh-ed25519-cert-v01@openssh.com host certificate
          Public key: ED25519-CERT SHA256:.* (re)
          Signing CA: ED25519 SHA256:.* (re)
          Key ID: "hello"
          Serial: 0
          Valid: forever
          Principals: (none)
          Critical Options: (none)
          Extensions: (none)

Read it back with our own code
  $ idbctl ssh cert read ./account-cert.pub
  ----------------------  --------------------------------------------------
  validity_period         ok
  key_fingerprint         SHA256:.* (re)
  signer_key_fingerprint  SHA256:.* (re)
  serial_number           0
  role                    host
  identifier              hello
  valid_after             always
  valid_before            forever
  ----------------------  --------------------------------------------------

Generate our own similar certificate
  $ idbctl ssh cert sign-host --principal hello --key account.pub --with account > account-cert.pub

Check we can read it ourselves
  $ idbctl ssh cert read ./account-cert.pub
  ----------------------  --------------------------------------------------
  validity_period         ok
  key_fingerprint         SHA256:.* (re)
  signer_key_fingerprint  SHA256:.* (re)
  serial_number           0
  role                    host
  identifier              SHA256:.* (re)
  principal               hello
  valid_after             always
  valid_before            forever
  ----------------------  --------------------------------------------------
 
Check OpenSSH can read it
  $ ssh-keygen -L -f ./account-cert.pub
  ./account-cert.pub:
          Type: ssh-ed25519-cert-v01@openssh.com host certificate
          Public key: ED25519-CERT SHA256:.* (re)
          Signing CA: ED25519 SHA256:.* (re)
          Key ID: "SHA256:.*" (re)
          Serial: 0
          Valid: forever
          Principals: 
                  hello
          Critical Options: (none)
          Extensions: (none)
