Initialize server and login
  $ bash $TESTDIR/fixture.sh

List existing roles (there is one)
  $ idbctl admin role list
    id  name    description
  ----  ------  ----------------------------------------------------------------------------
     1  root    The "root" role identifies a user that is able to do anything. It is created
                once at startup and should be deleted once a proper permission model is
                deployed.
  $ idbctl admin role delete -i 1
  Unable to delete role: Role is still in use
  [2]
  $ idbctl admin role update -i 1 -n hello
  $ idbctl admin role read -i 1
  id           1
  name         hello
  description  The "root" role identifies a user that is able to do anything. It is created once at startup and should be deleted once a proper permission model is deployed.
  permission   identity:*:*:*
  permission   tag:*:*:*
  permission   role:*:*:*
  permission   boundary:*:*:*
  member       root

