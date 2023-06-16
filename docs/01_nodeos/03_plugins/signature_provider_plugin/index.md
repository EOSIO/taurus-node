## Overview

The `signature_provider_plugin` provides the implemenation of `--signature-provider` parameter for `producer_plugin`.

In EOSIO-taurus, a new TPM signature provider is added allowing nodeos/cleos to sign transactions and/or blocks with non-extractable keys from TPM devices, to meet security requirements for enterprise deployments where non-extractable keys in hardware devices are preferred or required.

## Usage

```sh
# command-line
nodeos ... --signature-provider arg
```

## Options

These can be specified from both the `nodeos` command-line or the `config.ini` file. Please note the `TPM:<data>` arg type added in EOSIO-taurus.
```console
  --signature-provider arg (=EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV=KEY:5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3)
                                        Key=Value pairs in the form
                                        <public-key>=<provider-spec>
                                        Where:
                                           <public-key>    is a string form of
                                                           a valid EOSIO-Taurus public
                                                           key

                                           <provider-spec> is a string in the
                                                           form <provider-type>
                                                           :<data>

                                           <provider-type> is one of the types
                                                           below

                                           KEY:<data>      is a string form of
                                                           a valid EOSIO
                                                           private key which
                                                           maps to the provided
                                                           public key

                                           KEOSD:<data>    is the URL where
                                                           keosd is available
                                                           and the approptiate
                                                           wallet(s) are
                                                           unlocked

                                           TPM:<data>     indicates the key
                                                          resides in persistent
                                                          TPM storage, 'data'
                                                          is in the form
                                                          <tcti>|<pcr_list>
                                                          where optional 'tcti'
                                                          is the tcti and tcti
                                                          options, and optional
                                                          'pcr_list' is a comma
                                                          separated list of
                                                          PCRs to authenticate
                                                          with
```

## Notes

The TPM signature provider currently has a few limitations:

* It only operates with persistent keys stored in the owner hierarchy
* No additional authentication on the hierarchy is supported (for example if the hierarchy requires an additional password/PIN auth)
* For PCR based policies, which are supported, they can only be specified on the sha256 PCR bank
