#!/usr/bin/env python3

from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os


###############################################################
# snapshot creation on exit tests
# - start a nodeos
# - stop the nodeos
# - make sure a snapshot is created
###############################################################


Print = Utils.Print
args = TestHelper.parse_args({"--dump-error-details", "--keep-logs", "-v", "--leave-running", "--clean-run"})
Utils.Debug = args.v
producers = 1
totalNodes = producers
cluster = Cluster(walletd=True)
dumpErrorDetails = args.dump_error_details
keepLogs = args.keep_logs
dontKill = args.leave_running
killAll = args.clean_run
testSuccessful = False
killEosInstances = not dontKill
specificExtraNodeosArgs = {}

try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()

    extraNodeosArgs = " --resource-monitor-not-shutdown-on-threshold-exceeded"

    if cluster.launch(pnodes=producers, totalNodes=totalNodes, totalProducers=producers, useBiosBootFile=False,
                      dontBootstrap=True, prod_ha=False,
                      extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("Failed to stand up taurus cluster.")

    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    # now start the Raft sever with empty allowed subject names, should not be able to connect to each other any more
    nodes = cluster.getNodes()

    for node in nodes:
        node.kill()

    state_snapshot = os.path.join(Utils.getNodeDataDir(0), "state", "state_snapshot.bin")
    if not os.path.exists(state_snapshot):
        Utils.errorExit("Nodeos failed to create state_snapshot.bin on exit.")
    else:
        Utils.Print("Nodeos created state_snapshot.bin on exit.")

    # clean the shared_memory.pin and start the nodeos back to verify the snapshot is a valid one
    state_file = os.path.join(Utils.getNodeDataDir(0), "state", "shared_memory.bin")
    os.remove(state_file)

    swap_flags = dict()
    swap_flags["--snapshot"] = state_snapshot
    relaunched = nodes[0].relaunch(cachePopen=True, addSwapFlags=swap_flags)
    if not relaunched:
        Utils.errorExit("Nodeos failed to relaunch with the state_snapshot.bin created.")
    else:
        Utils.Print("Nodeos successfully relaunched with the state_snapshot.bin.")

    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Nodeos failed to produce blocks after loading from state snapshot.")
    else:
        Utils.Print("Nodeos can produce new blocks.")

    testSuccessful = True

finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
