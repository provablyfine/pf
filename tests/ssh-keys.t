  $ pf ssh key generate --format openssh > ed25519.key
  $ chmod og= ed25519.key
  $ ssh-keygen -l -f ed25519.key
  256 SHA256:[^(]+\(ED25519\) (re)

  $ pf ssh key generate -t rsa-3072 --format openssh > rsa-3072.key
  $ chmod og= rsa-3072.key
  $ ssh-keygen -l -f rsa-3072.key
  3072 SHA256:[^(]+\(RSA\) (re)

  $ pf ssh key generate -t ecdsa-256 --format openssh > ecdsa-256.key
  $ chmod og= ecdsa-256.key
  $ ssh-keygen -l -f ecdsa-256.key
  256 SHA256:[^(]+\(ECDSA\) (re)

  $ pf ssh key generate -t ecdsa-384 --format openssh > ecdsa-384.key
  $ chmod og= ecdsa-384.key
  $ ssh-keygen -l -f ecdsa-384.key
  384 SHA256:[^(]+\(ECDSA\) (re)

  $ pf ssh key generate -t ecdsa-521 --format openssh > ecdsa-521.key
  $ chmod og= ecdsa-521.key
  $ ssh-keygen -l -f ecdsa-521.key
  521 SHA256:[^(]+\(ECDSA\) (re)
