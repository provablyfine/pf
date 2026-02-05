
Generate private key ecdsa-256
  $ rm -f account account.pub >/dev/null 2>&1
  $ ssh-keygen -t ecdsa -b 256 -f account -N "" > /dev/null

Generate self-signed certificate ecdsa-256
  $ ssh-keygen -s account -I hello -h account.pub
  Signed host key account-cert.pub: id "hello" serial 0 valid forever\r (esc)

Read it back with our own code ecdsa-256
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

Generate our own similar certificate ecdsa-256
  $ idbctl ssh cert sign-host --principal hello --key account.pub --with account > account-cert.pub

Check we can read it ourselves ecdsa-256
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
 
Check OpenSSH can read it (ecdsa-256)
  $ ssh-keygen -L -f ./account-cert.pub
  ./account-cert.pub:
          Type: ecdsa-sha2-nistp256-cert-v01@openssh.com host certificate
          Public key: ECDSA-CERT SHA256:.* (re)
          Signing CA: ECDSA SHA256:.* (re)
          Key ID: "SHA256:.*" (re)
          Serial: 0
          Valid: forever
          Principals: 
                  hello
          Critical Options: (none)
          Extensions: (none)


Generate private key ecdsa-384
  $ rm -f account account.pub >/dev/null 2>&1
  $ ssh-keygen -t ecdsa -b 384 -f account -N "" > /dev/null

Generate self-signed certificate ecdsa-384
  $ ssh-keygen -s account -I hello -h account.pub
  Signed host key account-cert.pub: id "hello" serial 0 valid forever\r (esc)

Read it back with our own code ecdsa-384
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

Generate our own similar certificate ecdsa-384
  $ idbctl ssh cert sign-host --principal hello --key account.pub --with account > account-cert.pub

Check we can read it ourselves ecdsa-384
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
 
Check OpenSSH can read it (ecdsa-384)
  $ ssh-keygen -L -f ./account-cert.pub
  ./account-cert.pub:
          Type: ecdsa-sha2-nistp384-cert-v01@openssh.com host certificate
          Public key: ECDSA-CERT SHA256:.* (re)
          Signing CA: ECDSA SHA256:.* (re)
          Key ID: "SHA256:.*" (re)
          Serial: 0
          Valid: forever
          Principals: 
                  hello
          Critical Options: (none)
          Extensions: (none)


Generate private key ecdsa-521
  $ rm -f account account.pub >/dev/null 2>&1
  $ ssh-keygen -t ecdsa -b 521 -f account -N "" > /dev/null

Generate self-signed certificate ecdsa-521
  $ ssh-keygen -s account -I hello -h account.pub
  Signed host key account-cert.pub: id "hello" serial 0 valid forever\r (esc)

Read it back with our own code ecdsa-521
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

Generate our own similar certificate ecdsa-521
  $ idbctl ssh cert sign-host --principal hello --key account.pub --with account > account-cert.pub

Check we can read it ourselves ecdsa-521
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
 
Check OpenSSH can read it (ecdsa-521)
  $ ssh-keygen -L -f ./account-cert.pub
  ./account-cert.pub:
          Type: ecdsa-sha2-nistp521-cert-v01@openssh.com host certificate
          Public key: ECDSA-CERT SHA256:.* (re)
          Signing CA: ECDSA SHA256:.* (re)
          Key ID: "SHA256:.*" (re)
          Serial: 0
          Valid: forever
          Principals: 
                  hello
          Critical Options: (none)
          Extensions: (none)


