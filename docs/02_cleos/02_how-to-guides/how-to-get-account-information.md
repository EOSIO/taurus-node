## Goal

Query infomation of an EOSIO-Taurus account

## Before you begin

* Install the currently supported version of `cleos`

[[info | Note]]
| The cleos tool is bundled with the EOSIO-Taurus software. [Installing EOSIO-Taurus](../../00_install/index.md) will also install the cleos tool.

## Steps

Execute the command below:

```sh
cleos get account ACCOUNT_NAME
```
Where ACCOUNT_NAME = name of the existing account in the EOSIO-Taurus blockchain.

**Example Output**

```console
created: 2018-06-01T12:00:00.000
privileged: true
permissions:
     owner     1:    1 EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV
        active     1:    1 EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV
memory:
     quota:       unlimited  used:     3.004 KiB

net bandwidth:
     used:               unlimited
     available:          unlimited
     limit:              unlimited

cpu bandwidth:
     used:               unlimited
     available:          unlimited
     limit:              unlimited
```

[[info | Account Fields]]
| Depending on the EOSIO-Taurus network you are connected, you might see different fields associated with an account. That depends on which system contract has been deployed on the network.
