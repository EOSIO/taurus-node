`eosio-tpmtool` is a tool included in EOSIO-taurus, which can create keys in the TPM that are usable by nodeos. By design it is unable to remove keys. If more flexibly is desired (such as importing keys in to the TPM), a user may use external tools.

## Options

`eosio-tpmtool` supports the following options:

Option (=default) | Description
-|-
`--blocks-dir arg (="blocks")` | The location of the blocks directory (absolute path or relative to the current directory)
`--state-history-dir arg (="state-history")` | The location of the `state-history` directory (absolute path or relative to the current dir)
`-o [ --output-file ] arg` | The file to write the generated output to (absolute or relative path). If not specified then output is to `stdout`
`-f [ --first ] arg (=0)` | The first block number to log or the first block to keep if `trim-blocklog` specified
`-h [ --help ]` | Print this help message and exit
`-l [ --list ]` | List persistent TPM keys usable for EOSIO
`-c [ --create ]` | Create persistent TPM key
`-T [ --tcti ] arg` | Specify tcti and tcti options
`-p [ --pcr ] arg` | Add a PCR value to the policy of the created key. May be specified multiple times.
`-a [ --attest ] arg` |  Certify creation of the new key via key with given TPM handle
`--handle arg` | Persist key at given TPM handle (by default, find first available owner handle). Returns error code 100 if key already exists.

## Usage example:
Start up a TPM software simulator
```
swtpm socket -p 2222 --tpm2 --tpmstate dir=/tmp/tpmstate --ctrl type=tcp,port=2223 --flags startup-clear
```

Create a key
```
$ eosio-tpmtool -c -T swtpm:port=2222
PUB_R1_5cgfoaDAacuE6iEdJE1GjVfJ65ftGtgFS8ACNpHJPRbYCcuHMQ
```

Use the key as a signature provider in nodeos.
```
signature-provider = PUB_R1_5cgfoaDAacuE6iEdJE1GjVfJ65ftGtgFS8ACNpHJPRbYCcuHMQ=TPM:swtpm:port=2222
```

Create a key with a policy such that it can only be used if the given sha256 PCRs are the current value
```
$ eosio-tpmtool -c -T swtpm:port=2222 -p5 -p7
PUB_R1_5SnCFs9JzXCXQ1PivjqwygZzSc3Qu5jK5GXf8C3aYNManLz7zq
```
Use the key as a signature provider in nodes with the specified PCR policy. The policy is not saved anywhere, so you will need to specify it again here.
```
signature-provider = PUB_R1_5cgfoaDAacuE6iEdJE1GjVfJ65ftGtgFS8ACNpHJPRbYCcuHMQ=TPM:swtpm:port=2222|5,7
```
