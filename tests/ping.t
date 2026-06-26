Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .

pf ping prints pong
  $ pf -c config.json ping
  pong

pfa ping prints pong
  $ pfa -c config.json ping
  pong
