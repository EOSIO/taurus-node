#!/usr/bin/env python3

from testUtils import Utils
from TestHelper import TestHelper
from Cluster import Cluster
from rodeos_utils import RodeosUtils
from WalletMgr import WalletMgr

import time
import signal
from TestHelper import AppArgs

###############################################################
# rodeos_plugin_multi_kill_restart
# 
# 1- Launch a cluster of 2 Rodeos, verifies cluster is operating properly and it is stable.
# 2- Stop a rodeos node and verify the other rodeos is receiving blocks.
# 3- Restart rodeos and verify that rodeos receives blocks and has all the blocks
#
#This test repeats this scenario for idle state (empty blocks) vs under load test (generating transactions), Unix-socket, TCP/IP, 
# Clean vs non-clean mode restart, and SIGKILL, and SIGINT kill signals.
#
###############################################################
Print=Utils.Print

extraArgs=AppArgs()
extraArgs.add_bool("--eos-vm-oc-enable", "Use OC for rodeos")
extraArgs.add_bool("--clean-restart", "Use for clean restart of Rodeos")
extraArgs.add_bool("--load-test-enable", "Enable load test")
extraArgs.add_bool(flag="--unix-socket", help="Run ship over unix socket")

args=TestHelper.parse_args({"--dump-error-details","--keep-logs","-v","--leave-running","--clean-run"}, extraArgs)
enableOC=args.eos_vm_oc_enable
cleanRestart=args.clean_restart
enableLoadTest=args.load_test_enable
enableUnixSocket=args.unix_socket
Utils.Debug=args.v
killAll=args.clean_run
dumpErrorDetails=args.dump_error_details
dontKill=args.leave_running
killEosInstances=not dontKill
killWallet=not dontKill
keepLogs=args.keep_logs

TestHelper.printSystemInfo("BEGIN")
testSuccessful=False

def launch_cluster(num_rodeos, unix_socket, cleanRestart, killSignal, eos_vm_oc_enable=False):
    global testSuccessful
    testSuccessful=False
    walletMgr=WalletMgr(True)
    cluster=Cluster(walletd=True)
    cluster.setWalletMgr(walletMgr)

    try:
        cluster.killall(allInstances=killAll)
        cluster.cleanup()

        OCArg = " --eos-vm-oc-enable " if eos_vm_oc_enable else " "

        assert num_rodeos == 2, "Update test for different # of rodeos"
        if unix_socket:
            listenArg1 = " --wql-unix-listen ./var/lib/node_01/rodeos0.sock --wql-listen disable "
            listenArg2 = " --wql-unix-listen ./var/lib/node_02/rodeos1.sock --wql-listen disable "
        else:
            listenArg1 = " --wql-listen 127.0.0.1:8880 "
            listenArg2 = " --wql-listen 127.0.0.1:8881 "

        specificExtraNodeosArgs={
            0: "--plugin eosio::net_api_plugin --wasm-runtime eos-vm-jit --chain-state-db-size-mb=131072 --plugin eosio::txn_test_gen_plugin ",
            1: "--chain-state-db-size-mb=131072 --disable-replay-opts --plugin b1::rodeos_plugin --filter-name test.filter --filter-wasm ./tests/test_filter.wasm " + OCArg + listenArg1,
            2: "--chain-state-db-size-mb=131072 --disable-replay-opts --plugin b1::rodeos_plugin --filter-name test.filter --filter-wasm ./tests/test_filter.wasm " + OCArg + listenArg2
        }

        assert cluster.launch(
            pnodes=1,
            prodCount=1,
            totalProducers=1,
            totalNodes=1+num_rodeos,
            useBiosBootFile=False,
            loadSystemContract=False,
            extraNodeosArgs=" --plugin eosio::trace_api_plugin --trace-no-abis",
            specificExtraNodeosArgs=specificExtraNodeosArgs)

        time.sleep(10)  # Leave rodeos nodes enough time to get fully launched

        prodNode = cluster.getNode(0)
        rodeosNode1 = cluster.getNode(1)

        rodeosCluster=RodeosUtils(cluster, num_rodeos, unix_socket)
        rodeosCluster.start()

        Print("Testing cluster of {} rodeos nodes connecting through {}"\
            .format(num_rodeos, (lambda x: 'Unix Socket' if (x==True) else 'TCP')(unix_socket)))

        if enableLoadTest:
            Print("Starting load generation")
            rodeosCluster.startLoad()
        # Big enough to have new blocks produced
        numBlocks=120
        assert rodeosCluster.produceBlocks(numBlocks), "Nodeos failed to produce {} blocks for a cluster of {} rodeos node"\
            .format(numBlocks, num_rodeos)

        for i in range(num_rodeos):
            assert rodeosCluster.allBlocksReceived(numBlocks, i), "Rodeos #{} did not receive {} blocks in a cluster of {} rodeos node"\
            .format(i, numBlocks, num_rodeos)

        # Stop rodeosId=1
        rodeosKilledId=1
        Print("Stopping rodeos #{} with kill -{} signal".format(rodeosKilledId, killSignal))
        rodeosNode1.kill(killSignal)

        # Producing 10 more blocks
        currentBlockNum=prodNode.getHeadBlockNum()
        numBlocks= currentBlockNum + 10
        assert rodeosCluster.produceBlocks(numBlocks), "Nodeos failed to produce {} blocks for a cluster of {} rodeos node"\
            .format(numBlocks, num_rodeos)

        # Restarting rodeos
        Print("Restarting rodeos #{}".format(rodeosKilledId))
        rodeosCluster.relaunchNode(rodeosNode1, clean=cleanRestart)

        rodeosNode1.waitForLibToAdvance()

        # Verify that the other rodeos instances receiving blocks
        for i in range(num_rodeos):
            if i != rodeosKilledId:
                assert rodeosCluster.allBlocksReceived(numBlocks, i), "Rodeos #{} did not receive {} blocks after rodeos #{} shutdown"\
                    .format(i, numBlocks, rodeosKilledId)

        # Producing 10 more blocks after rodeos restart
        currentBlockNum=prodNode.getHeadBlockNum()
        numBlocks= currentBlockNum + 10
        assert rodeosCluster.produceBlocks(numBlocks), "Nodeos failed to produce {} blocks for a cluster of {} rodeos node"\
            .format(numBlocks, num_rodeos)

        # verify that rodeos receives all blocks from start to now
        assert rodeosCluster.allBlocksReceived(numBlocks, rodeosKilledId), "Rodeos #{} did not receive {} blocks after it restarted"\
                .format(rodeosKilledId, numBlocks)

        # verify that all rodeos nodes receiving blocks without interruption
        currentBlockNum=prodNode.getHeadBlockNum()
        for j in range(num_rodeos):
            assert rodeosCluster.allBlocksReceived(numBlocks, j), "Rodeos #{} did not receive {} blocks"\
                .format(j, numBlocks)

        if enableLoadTest:
            rodeosCluster.stopLoad()

        testSuccessful=True
    finally:
        TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances, killWallet, keepLogs, killAll, dumpErrorDetails)


# Test cases: (2 rodeos)
numRodeos=[2]
NumTestCase=len(numRodeos)
for i in range(NumTestCase):
    # SIGTERM is similar to SIGINT. Drop it to reduce testing duration
    for killSignal in [signal.SIGKILL, signal.SIGINT]:
        if killSignal == signal.SIGKILL and cleanRestart == False: # With ungraceful shutdown, clean restart is required.
            continue
        launch_cluster(numRodeos[0], enableUnixSocket, cleanRestart, killSignal, enableOC)

errorCode = 0 if testSuccessful else 1
exit(errorCode)
