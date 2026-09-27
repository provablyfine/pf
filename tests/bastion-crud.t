Initialize server and login
  $ bash $TESTDIR/fixture.sh
  .* (re)

List empty bastions
  $ pfa -c config.json bastion list

Create bastion 1 (minimal)
  $ pfa -c config.json bastion create --url http://bastion1.example.com
  $ BASTION1_ID=$(pfa -c config.json bastion list -q)
  $ echo "BASTION1_ID=$BASTION1_ID"
  BASTION1_ID=1

Create bastion 2 (with ssh-proxy-jump)
  $ pfa -c config.json bastion create --url http://bastion2.example.com --ssh-proxy-jump user@jump.example.com:22

Create tag for bastion 3
  $ pfa -c config.json tag create -n env -v prod
  $ TAG_ID=$(pfa -c config.json tag list -q)

Create bastion 3 (with tag)
  $ pfa -c config.json bastion create --url http://bastion3.example.com -t $TAG_ID
  $ BASTION3_ID=$(pfa -c config.json bastion list -q | tail -1)
  $ echo "BASTION3_ID=$BASTION3_ID"
  BASTION3_ID=3

Create bastion 4 (-t with no values means visible to no one)
  $ pfa -c config.json bastion create --url http://bastion4.example.com -t
  $ BASTION4_ID=$(pfa -c config.json bastion list -q | tail -1)
  $ pfa -c config.json bastion read -i $BASTION4_ID
  id    4
  url   http://bastion4.example.com
  tags  none (visible to no one)
  $ pfa -c config.json bastion delete -i $BASTION4_ID

List bastions (text format)
  $ pfa -c config.json bastion list
    id  url                          ntags
  ----  ---------------------------  -------
     1  http://bastion1.example.com  all
     2  http://bastion2.example.com  all
     3  http://bastion3.example.com  1

List bastions (quiet format)
  $ pfa -c config.json bastion list -q
  1
  2
  3

List bastion by id (text)
  $ pfa -c config.json bastion list -i $BASTION1_ID
    id  url                          ntags
  ----  ---------------------------  -------
     1  http://bastion1.example.com  all

List bastion by id (json)
  $ pfa -c config.json bastion list -i $BASTION3_ID -f json
  [
    {
      "id": 3,
      "url": "http://bastion3.example.com",
      "ssh_proxy_jump": null,
      "tag_list": [
        {
          "name": "env",
          "value": "prod"
        }
      ]
    }
  ]


Read bastion 1 (text)
  $ pfa -c config.json bastion read -i $BASTION1_ID
  id    1
  url   http://bastion1.example.com
  tags  all (unrestricted)

Read bastion 2 (text, with ssh-proxy-jump)
  $ pfa -c config.json bastion read -i 2
  id              2
  url             http://bastion2.example.com
  ssh_proxy_jump  user@jump.example.com:22
  tags            all (unrestricted)

Read bastion 3 (text, with tag)
  $ pfa -c config.json bastion read -i $BASTION3_ID
  id   3
  url  http://bastion3.example.com
  tag  env=prod

Read bastion (json format)
  $ pfa -c config.json bastion read -i $BASTION3_ID -f json
  {
    "id": 3,
    "url": "http://bastion3.example.com",
    "ssh_proxy_jump": null,
    "tag_list": [
      {
        "name": "env",
        "value": "prod"
      }
    ]
  }

Update bastion 1 url
  $ pfa -c config.json bastion update -i $BASTION1_ID --url http://bastion1-updated.example.com

Read bastion 1 to verify update
  $ pfa -c config.json bastion read -i $BASTION1_ID
  id    1
  url   http://bastion1-updated.example.com
  tags  all (unrestricted)

Update bastion 2 ssh-proxy-jump
  $ pfa -c config.json bastion update -i 2 --ssh-proxy-jump admin@new-jump.example.com:2222

Read bastion 2 to verify update
  $ pfa -c config.json bastion read -i 2
  id              2
  url             http://bastion2.example.com
  ssh_proxy_jump  admin@new-jump.example.com:2222
  tags            all (unrestricted)

Update bastion 3 tags: -t with no values means visible to no one
  $ pfa -c config.json bastion update -i $BASTION3_ID -t
  $ pfa -c config.json bastion read -i $BASTION3_ID
  id    3
  url   http://bastion3.example.com
  tags  none (visible to no one)

Update bastion 3 tags: --unrestrict-tags restores visible to everyone
  $ pfa -c config.json bastion update -i $BASTION3_ID --unrestrict-tags
  $ pfa -c config.json bastion read -i $BASTION3_ID
  id    3
  url   http://bastion3.example.com
  tags  all (unrestricted)

Update bastion 3 tags: -t with values sets a concrete tag list
  $ pfa -c config.json bastion update -i $BASTION3_ID -t env=prod
  $ pfa -c config.json bastion read -i $BASTION3_ID
  id   3
  url  http://bastion3.example.com
  tag  env=prod

Combining --tag and --unrestrict-tags is rejected
  $ pfa -c config.json bastion update -i $BASTION3_ID -t env=prod --unrestrict-tags
  Cannot combine --tag and --unrestrict-tags
  [2]

Mixing numeric tag ids and name=value tags in one --tag is rejected
  $ pfa -c config.json bastion update -i $BASTION3_ID -t $TAG_ID env=prod
  Cannot mix numeric tag ids and name=value tags
  [2]

Read non-existent bastion (error)
  $ pfa -c config.json bastion read -i 9999
  .* (re)
  [2]

Update non-existent bastion (error)
  $ pfa -c config.json bastion update -i 9999 --url http://test.example.com
  .* (re)
  [2]

Delete bastion 1
  $ pfa -c config.json bastion delete -i $BASTION1_ID

Delete non-existent bastion (error)
  $ pfa -c config.json bastion delete -i 9999
  .* (re)
  [2]

Verify bastion 1 is gone
  $ pfa -c config.json bastion list -q
  2
  3

Delete bastions 2 and 3
  $ pfa -c config.json bastion delete -i 2
  $ pfa -c config.json bastion delete -i $BASTION3_ID

Verify all bastions are gone
  $ pfa -c config.json bastion list -q
