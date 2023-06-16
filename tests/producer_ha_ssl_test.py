#!/usr/bin/env python3

from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os


###############################################################
#   Producer ha SSL and allowed subject names support
# Creates a cluster with
# - with ssl support
#   - with correct or wrong allowed subject names
###############################################################


Print = Utils.Print
args = TestHelper.parse_args({"--dump-error-details", "--keep-logs", "-v", "--leave-running", "--clean-run"})
Utils.Debug = args.v
producers = 3
totalNodes = producers
cluster = Cluster(walletd=True)
dumpErrorDetails = args.dump_error_details
keepLogs = args.keep_logs
dontKill = args.leave_running
killAll = args.clean_run
testSuccessful = False
killEosInstances = not dontKill
specificExtraNodeosArgs = {}


# create_ha_config for this tests only
def create_ha_config(producers, valid_subject_names):
    subject_names = []
    if valid_subject_names:
        subject_names = [
            "/O=taurus-node test/CN=taurus-node test CA",
            "/CN=bp01.taurus-node-test.local",
            "/CN=bp02.taurus-node-test.local",
            "/CN=bp03.taurus-node-test.local"
        ]

    tests_dir = os.path.dirname(os.path.realpath(__file__))
    certs_dir = os.path.join(tests_dir, "producer_ha_certs")

    for i in range(producers):
        Node.create_ha_config(
            i,
            enable_ssl=True,
            server_cert_file=os.path.join(certs_dir, "bp{0:02d}.crt".format(i+1)),
            server_key_file=os.path.join(certs_dir, "bp{0:02d}.key".format(i+1)),
            root_cert_file=os.path.join(certs_dir, "ca.pem"),
            allowed_ssl_subject_names=subject_names
        )


try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()

    # start the producer_ha cluster with certs and correct allowed subject names
    create_ha_config(producers, True)

    path_to_config_ha = os.getcwd()
    extraNodeosArgs = " --resource-monitor-not-shutdown-on-threshold-exceeded"
    for i in range(producers):
        specificExtraNodeosArgs[i] = \
            " --plugin eosio::producer_ha_plugin --producer-ha-config {}/config_ha_{}.json".format(
                path_to_config_ha, i)
    if cluster.launch(pnodes=producers, totalNodes=totalNodes, totalProducers=producers, useBiosBootFile=False,
                      dontBootstrap=True, specificExtraNodeosArgs=specificExtraNodeosArgs, prod_ha=True,
                      extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("Failed to stand up taurus cluster with producer_ha + ssl.")

    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    # now start the Raft sever with empty allowed subject names, should not be able to connect to each other any more
    nodes = cluster.getNodes()

    for node in nodes:
        node.kill()

    # make subject names list invalid
    create_ha_config(producers, valid_subject_names=False)

    for node in nodes:
        res = node.relaunch(cachePopen=True)
        if not res:
            Utils.errorExit("Relaunching node failed")
    cluster.setNodes(nodes)

    # wait for 10 blocks in case the producer_ha still have some blocks to apply to the producer_plugin
    if cluster.waitOnClusterSync(timeout=45, blockAdvancing=10):
        Utils.errorExit("Cluster still produce blocks.")
    else:
        Utils.Print("Cluster not producing")

    testSuccessful = True

finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
