
It is only intended for debugging or performance evaluations, not for production.

## Rebuild contracts

The prebuilt contracts are already checked into the repo. If rebuilding the contracts in this directory from source is needed, you need to specify `-DEOSIO_CDT_ROOT=$TARUS_CDT3_BUILD_DIR -DEOSIO_COMPILE_TEST_CONTRACTS=ON` during cmake configuration.

## Script Usage

After the project is built, two scripts (`start_nodeos.sh` and `bootstrap.sh`) will be generated in the build/contracts directory. First, run `start_nodeos.sh` in one terminal window and then run `bootstrap.sh` in another terminal window. After `bootstrap.sh` is done, you can use `cleos` to directly create new account and deploy contracts using `cleos`.
