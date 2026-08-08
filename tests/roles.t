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
  grant        type:       bastion
               filter:     *
               permission: create read update.* delete
  grant        type:       audit-log
               filter:     *
               permission: read


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

An "ssh" grant round-trips through the wire schema. Nothing evaluates it yet:
this asserts storage and display only. Note how null renders as "*" (the whole
axis) and an empty list as "!" (explicitly nothing).
  $ pfa -c config.json role create -n ssh-new
  $ SSH_ROLE_ID=$(pfa -c config.json role list -n ssh-new -q)
  $ pfa -c config.json role grant -i $SSH_ROLE_ID --set <<EOF
  > - type: ssh
  >   filter:
  >     name: null
  >     tag_list:
  >       - name: env
  >         value: dev
  >     boundary_list: null
  >   permission:
  >     username_list: ["root", "{self}"]
  >     capability_list: ["shell", "pty", "agent-forwarding"]
  >     command_list: []
  > - type: ssh
  >   filter:
  >     name: null
  >     tag_list: null
  >     boundary_list: null
  >   permission:
  >     username_list: null
  >     capability_list: null
  >     command_list: ["git-upload-pack /repo"]
  > EOF
  $ pfa -c config.json role read -i $SSH_ROLE_ID | grep -A 2 'type: *ssh'
  grant        type:       ssh
               filter:     tag_list:env=dev
               permission: username_list:root,{self} capability_list:shell,pty,agent-forwarding command_list:!
  grant        type:       ssh
               filter:     *
               permission: username_list:* capability_list:* command_list:git-upload-pack /repo

"pfa grant ssh" emits the new type. An unset axis is an empty list; the
--*-all flags spell the whole axis as null.
  $ pfa -c config.json grant ssh --tag env=dev --username root --capability shell pty
  type: ssh
  filter:
    name: null
    tag_list:
      - name: env
        value: dev
    boundary_list: null
  permission:
    username_list:
      - root
    capability_list:
      - shell
      - pty
    command_list: []
  $ pfa -c config.json grant ssh --username-all --capability-all --cmd-all -f json
  {
    "type": "ssh",
    "filter": {
      "name": null,
      "tag_list": null,
      "boundary_list": null
    },
    "permission": {
      "username_list": null,
      "capability_list": null,
      "command_list": null
    }
  }
  $ pfa -c config.json grant ssh --username root
  Grant is empty. Pass --capability, --cmd, or one of their --*-all forms.
  [2]
  $ pfa -c config.json grant ssh --capability shell
  Grant has no username. Pass --username or --username-all.
  [2]
  $ pfa -c config.json grant ssh --username root --capability nonsense 2>&1 | tail -1
  pfa grant ssh: error: argument --capability: invalid choice: * (glob)

Legacy grant types are no longer produced by the CLI, but are still accepted on
the wire for older clients. They are normalized to "ssh" on the way in, so an
old client cannot reintroduce a legacy row.
  $ pfa -c config.json role create -n legacy
  $ LEGACY_ROLE_ID=$(pfa -c config.json role list -n legacy -q)
  $ pfa -c config.json role grant -i $LEGACY_ROLE_ID --set <<EOF
  > - type: ssh-shell
  >   filter:
  >     name: null
  >     tag_list: [{name: env, value: dev}]
  >     boundary_list: null
  >   permission:
  >     username_list: ["root"]
  >     permit_agent_forwarding: false
  >     permit_x11_forwarding: true
  > EOF
  $ pfa -c config.json role read -i $LEGACY_ROLE_ID | grep -A 2 'type:'
  grant        type:       ssh
               filter:     tag_list:env=dev
               permission: username_list:root capability_list:shell,pty,user-rc,x11-forwarding command_list:!

An "ssh" permission denoting the empty atom set is rejected
  $ pfa -c config.json role grant -i $SSH_ROLE_ID --set <<EOF
  > - type: ssh
  >   filter: {name: null, tag_list: null, boundary_list: null}
  >   permission:
  >     username_list: ["root"]
  >     capability_list: []
  >     command_list: []
  > EOF
  Request invalid. Value error, capability_list and command_list must not both be empty: body.grant_list.0.ssh.permission
  [2]
