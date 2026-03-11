Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List existing roles (there is one)
  $ idbctl admin role list
    id  name    description
  ----  ------  ----------------------------------------------------------------------------
     1  root    The "root" role identifies a user that is able to do anything. It is created
                once at startup and should be deleted once a proper permission model is
                deployed.
  $ idbctl admin role delete -i 1
  Role is still in use
  [2]
  $ idbctl admin role update -i 1 -n hello
  $ idbctl admin role read -i 1
  id           1
  name         hello
  description  The "root" role identifies a user that is able to do anything. It is created once at startup and should be deleted once a proper permission model is deployed.
  member       root
  grant        type:       identity
               filter:     *
               permission: create read update.* delete add_tag_list:* del_tag_list:* invite_list:*
  grant        type:       ssh
               filter:     *
               permission: username_list:* force_command_list:* permit_pty permit_user_rc permit_x11_forwarding permit_agent_forwarding permit_port_forwarding
  grant        type:       tag
               filter:     *
               permission: create read delete
  grant        type:       role
               filter:     *
               permission: create read update.* delete
  grant        type:       boundary
               filter:     *
               permission: create read update.* delete

Create tags to be able to define tag-related permissions in role
  $ idbctl admin tag create -n env -v dev
  $ idbctl admin tag create -n env -v preprod
  $ idbctl admin tag create -n env -v prod

Create a new role
  $ idbctl admin role create -n developer
  $ ROLE_ID=$(idbctl admin role list -n developer -q)
  $ idbctl admin role grant -i $ROLE_ID --set <<EOF
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
  > - type: ssh
  >   filter:
  >     name: null
  >     tag_list:
  >       - name: env
  >         value: dev
  >     boundary_list: null
  >   permission:
  >     username_list: ["root"]
  >     force_command_list: null
  >     permit_pty: true
  >     permit_user_rc: true
  >     permit_agent_forwarding: false
  >     permit_x11_forwarding: false
  >     permit_port_forwarding: true
  > EOF
