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
  Unable to delete role. Role is still in use
  [2]
  $ idbctl admin role update -i 1 -n hello
  $ idbctl admin role read -i 1
  id: 1
  name: hello
  description: The "root" role identifies a user that is able to do anything. It is
    created once at startup and should be deleted once a proper permission model is
    deployed.
  grant_list:
    - type: identity
      filter:
        name: null
        tag_list: null
        boundary_list: null
      permission:
        create:
          allowed: true
          allowed_tag_list: null
          required_boundary_list: null
        read: true
        update: null
        delete: true
        add_tag_list: null
        del_tag_list: null
        invite_list: null
    - type: ssh
      filter:
        name: null
        tag_list: null
        boundary_list: null
      permission:
        force_command_list: null
        username_list: null
        permit_pty: true
        permit_user_rc: true
        permit_x11_forwarding: true
        permit_agent_forwarding: true
        permit_port_forwarding: true
    - type: tag
      filter:
        name_value: null
      permission:
        read: true
        delete: true
        create: true
    - type: role
      filter:
        name: null
      permission:
        read: true
        delete: true
        create: true
        update: null
    - type: boundary
      filter:
        name: null
      permission:
        read: true
        delete: true
        create: true
        update: null
  member_list:
    - id: 1
      name: root

Create tags to be able to define tag-related permissions in role
  $ idbctl admin tag create -n env -v dev
  $ idbctl admin tag create -n env -v preprod
  $ idbctl admin tag create -n env -v prod

Create a new role
  $ idbctl admin role create -n developer
  $ ROLE_ID=$(idbctl admin role list -n developer -q)
  $ idbctl admin role grant -i $ROLE_ID set <<EOF
  > - type: identity
  >   filter:
  >     name: null
  >     tag_list: ["env=dev"]
  >     boundary_list: null
  >   permission:
  >     create:
  >       allowed: true
  >       allowed_tag_list: ["env=dev"]
  >       required_boundary_list: null
  >     read: true
  >     update: null
  >     delete: true
  >     add_tag_list: ["env=dev"]
  >     del_tag_list: ["env=dev"]
  >     invite_list: ["email"]
  > - type: ssh
  >   filter:
  >     name: null
  >     tag_list: ["env=dev"]
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
