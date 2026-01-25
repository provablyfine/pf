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

Create tags to be able to define tag-related permissions in role
  $ idbctl admin tag create -n env -v dev
  $ idbctl admin tag create -n env -v preprod
  $ idbctl admin tag create -n env -v prod

Create a new role
  $ idbctl admin role create -n developer
  $ ROLE_ID=$(idbctl admin role list -n developer -q)
  $ idbctl admin role permission -i $ROLE_ID --stdin <<EOF
  > identity:create:*:*
  > identity:add-tag:created_by/self:tag/env=dev
  > identity:del-tag:tag/env=dev:*
  > identity:ssh-shell:tag/env=dev:username/root
  > identity:ssh-sftp:tag/env=dev:username/app
  > identity:ssh-forward-remote:tag/env=prod:rport/8080
  > identity:ssh-forward-local:tag/env=prod:rport/8080
  > EOF
