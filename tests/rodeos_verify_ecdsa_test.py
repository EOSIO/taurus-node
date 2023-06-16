#!/usr/bin/env python3

from testUtils import Utils
from TestHelper import TestHelper
from rodeos_utils import RodeosCommon, RodeosCluster

import json
import subprocess
import time

###############################################################################
# rodeos_test.py
#
# rodeos verify ECDSA signatures test
#
# This test creates a producer node, a SHiP node, and a rodeos instance. The 
# test pushes a transaction to the producer node, to a contract that verifies 
# ECDSA signatures. Only if the signature is verified can the transaction be
# processed. Then from the rodeos instance we verify the blocks are exactly
# the same between nodeos and rodeos.
#
###############################################################################

# Parse command line arguments
args = TestHelper.parse_args({"-v", "--clean-run", "--dump-error-details", "--leave-running", "--keep-logs"})
Utils.Debug = args.v
stateHistoryStride = 10
stateHistoryEndpoint = "127.0.0.1:8080"

testSuccessful = False
TestHelper.printSystemInfo("BEGIN")

with RodeosCluster(args.dump_error_details,
        args.keep_logs,
        args.leave_running,
        args.clean_run, 
        {},
        'test.filter', './tests/test_filter.wasm',
        producerExtraArgs="--plugin eosio::state_history_plugin --trace-history " +
                          "--chain-state-history " +
                          "--state-history-stride {} ".format(stateHistoryStride) +
                          "--state-history-endpoint {} ".format(stateHistoryEndpoint) +
                          "--plugin eosio::net_api_plugin --wasm-runtime eos-vm-jit " +
                          "--cpu-effort-percent 60") as rodeosCluster:
    assert rodeosCluster.waitRodeosReady(), "Rodeos failed to stand up"

    # Create an account and publish test contract
    Utils.Print("Create a new account alice from the producer node")
    testAcctName = "alice"
    prodNode = rodeosCluster.prodNode
    testAcct = RodeosCommon.createAccount(prodNode, testAcctName)

    Utils.Print("Publish verify_ecdsa contract")
    contractDir = "unittests/test-contracts/verify_ecdsa"
    RodeosCommon.publishContract(prodNode, testAcct, contractDir)

    trx = {
        "actions": [{
            "account": testAcctName,
            "name": "validkey",
            "authorization": [{
                "actor": testAcctName,
                "permission": "active"}],
            "data": {
                "pubkey" : "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzjca5ANoUF+XT+4gIZj2/X3V2UuT\nE9MTw3sQVcJzjyC/p7KeaXommTC/7n501p4Gd1TiTiH+YM6fw/YYJUPSPg==\n-----END PUBLIC KEY-----"
            }
        },
        {
            "account": testAcctName,
            "name": "verify",
            "authorization": [{
                "actor": testAcctName,
                "permission": "active"}],
            "data": {
                "msg": "message to sign",
                "sig": "MEYCIQCi5byy/JAvLvFWjMP8ls7z0ttP8E9UApmw69OBzFWJ3gIhANFE2l3jO3L8c/kwEfuWMnh8q1BcrjYx3m368Xc/7QJU",
                "pubkey" : "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzjca5ANoUF+XT+4gIZj2/X3V2UuT\nE9MTw3sQVcJzjyC/p7KeaXommTC/7n501p4Gd1TiTiH+YM6fw/YYJUPSPg==\n-----END PUBLIC KEY-----"
            }
        }]
    }

    # Verification
    block_num = RodeosCommon.verifyProducerNode(prodNode, trx, testAcctName)
    RodeosCommon.verifyRodeos(rodeosCluster, 0, trx, block_num, testAcctName)

    testSuccessful=True
    rodeosCluster.setTestSuccessful(True)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
