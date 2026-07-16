Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List existing roles (there is one)
  $ pfa -c config.json role list
    id  name    description
  ----  ------  ----------------------------------------------------------------------------
     1  root    The "root" role identifies a user that is able to do anything. It is created
                once at startup and should be deleted once a proper permission model is
                deployed.
  $ pfa -c config.json role delete -i 1
  Role is still in use
  [2]
  $ pfa -c config.json role update -i 1 -n hello
  $ pfa -c config.json role read -i 1
  id           1
  name         hello
  description  The "root" role identifies a user that is able to do anything. It is created once at startup and should be deleted once a proper permission model is deployed.
  member       root
  grant        type:       identity
               filter:     *
               permission: create read update.* delete add_tag_list:* del_tag_list:* invite_list:*
  grant        type:       tag
               filter:     *
               permission: create read delete
  grant        type:       role
               filter:     *
               permission: create read update.* delete
  grant        type:       boundary
               filter:     *
               permission: create read update.* delete
  grant        type:       tenant
               filter:     *
               permission: create read update.display_name update.is_enabled delete
  grant        type:       auth
               filter:     *
               permission: create read update.* delete

Create tags to be able to define tag-related permissions in role
  $ pfa -c config.json tag create -n env -v dev
  $ pfa -c config.json tag create -n env -v preprod
  $ pfa -c config.json tag create -n env -v prod

Create a new role
  $ pfa -c config.json role create -n developer
  $ ROLE_ID=$(pfa -c config.json role list -n developer -q)
  $ pfa -c config.json role grant -i $ROLE_ID --set <<EOF
  > - type: identity
  >   filter:
  >     name: null
  >     tag_list:
  >       - name: env
  >         value: dev
  >     boundary_list: null
  >   permission:
  >     create:
  >       allowed: true
  >       allowed_tag_list:
  >         - name: env
  >           value: dev
  >       required_boundary_list: null
  >     read: true
  >     update: null
  >     delete: true
  >     add_tag_list: [{name: "env", value: "dev"}]
  >     del_tag_list:
  >       - name: env
  >         value: dev
  >     invite_list: ["email"]
  > - type: ssh-shell
  >   filter:
  >     name: null
  >     tag_list:
  >       - name: env
  >         value: dev
  >     boundary_list: null
  >   permission:
  >     username_list: ["root"]
  >     permit_agent_forwarding: false
  >     permit_x11_forwarding: false
  > EOF

Add first member to developer role
  $ pfa -c config.json identity create -n user1
  $ pfa -c config.json role member -i $ROLE_ID -a user1

Add second member to role that already has a member
  $ pfa -c config.json identity create -n user2
  $ pfa -c config.json role member -i $ROLE_ID -a user2
  $ pfa -c config.json role read -i $ROLE_ID | grep ^member
  member       user1
  member       user2

Adding a grant to the active role (root, id=1) should succeed
  $ pfa -c config.json grant tag --create | pfa -c config.json role grant -i 1 --add

Removing a grant from the active role should fail
  $ pfa -c config.json role read -i 1 -f json | jq '.grant_list[-1]' | pfa -c config.json role grant -i 1 --del
  Not allowed to remove grants from the active session role
  [2]
