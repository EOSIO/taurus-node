#!/usr/bin/env python3

from Cluster import Cluster
from Node import Node
from TestHelper import AppArgs
from TestHelper import TestHelper
from testUtils import Account
from testUtils import Utils
from WalletMgr import WalletMgr
from rodeos_utils import RodeosCommon, RodeosUtils

import json
import subprocess

###############################################################################
# rodeos_plugin_verify_ecdsa_test.py
#
# rodeos-plugin verify ECDSA signatures test
#
# This test creates a producer node (node #0), and a node (node #1) with
# rodeos-plugin enabled. The test pushes a transaction to node #0, to a
# contract that verifies ECDSA signatures. Only if the signature is verified
# can the transaction be processed. Then from the rodeos-plugin-enabled node #1
# we verify the blocks are exactly the same between the 2 nodes.
#
###############################################################################

# Parse command line arguments
extraArgs = AppArgs()
args = TestHelper.parse_args({"-v", "--clean-run", "--dump-error-details", "--leave-running", "--keep-logs"}, extraArgs)
Utils.Debug = args.v
killAll = args.clean_run
dumpErrorDetails = args.dump_error_details
dontKill = args.leave_running
killEosInstances = not dontKill
killWallet = not dontKill
keepLogs = args.keep_logs
walletMgr = WalletMgr(True)
cluster = Cluster(walletd=True)
cluster.setWalletMgr(walletMgr)

testSuccessful = False
num_rodeos=1

try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()
    assert cluster.launch(
        pnodes=1,
        prodCount=1,
        totalProducers=1,
        totalNodes=1 + num_rodeos,
        useBiosBootFile=False,
        loadSystemContract=False,
        extraNodeosArgs=" --plugin eosio::trace_api_plugin --trace-no-abis",
        specificExtraNodeosArgs={0: ("--plugin b1::rodeos_plugin " +
                                     "--rdb-options-file " +
                                     "rocksdb_options.ini")})

    prodNode = cluster.getNode(0)

    rodeosCluster=RodeosUtils(cluster, num_rodeos)
    rodeosCluster.start()

    Utils.Print("create a new account alice from the producer node")
    testAcctName = "alice"
    testAcct = RodeosCommon.createAccount(prodNode, testAcctName)

    Utils.Print("Publish verify_ecdsa contract")
    contractDir = "unittests/test-contracts/verify_ecdsa"
    trans = RodeosCommon.publishContract(prodNode, testAcct, contractDir)

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

    block_num = RodeosCommon.verifyProducerNode(prodNode, trx, testAcctName)
    RodeosCommon.verifyRodeos(rodeosCluster, 0, trx, block_num, testAcctName)

    testSuccessful = True
finally:
    TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances, killWallet, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
