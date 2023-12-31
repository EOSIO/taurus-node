#!/usr/bin/env python3

from testUtils import Utils
from Cluster import Cluster
from TestHelper import TestHelper

import random
import subprocess
import signal
import time

###############################################################
# validate-dirty-db
#
# Test for validating NO dirty db flag any more after repeated nodeos restart attempts
#
###############################################################


Print=Utils.Print
errorExit=Utils.errorExit

args = TestHelper.parse_args({"--keep-logs","--dump-error-details","-v","--leave-running","--clean-run"})
debug=args.v
pnodes=1
topo="mesh"
delay=1
chainSyncStrategyStr=Utils.SyncResyncTag
total_nodes = pnodes
killCount=1
killSignal=Utils.SigKillTag

killEosInstances= not args.leave_running
dumpErrorDetails=args.dump_error_details
keepLogs=args.keep_logs
killAll=args.clean_run

seed=1
Utils.Debug=debug
testSuccessful=False

def runNodeosAndGetOutput(myTimeout=3):
    """Startup nodeos, wait for timeout (before forced shutdown) and collect output. Stdout, stderr and return code are returned in a dictionary."""
    Print("Launching nodeos process.")
    cmd="programs/nodeos/nodeos --config-dir etc/eosio/node_bios --data-dir var/lib/node_bios --verbose-http-errors --http-validate-host=false --terminate-at-block 5"
    Print("cmd: %s" % (cmd))
    proc=subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if debug: Print("Nodeos process launched.")

    output={}
    try:
        if debug: Print("Setting nodeos process timeout.")
        outs,errs = proc.communicate(timeout=myTimeout)
        if debug: Print("Nodeos process has exited.")
        output["stdout"] = outs.decode("utf-8")
        output["stderr"] = errs.decode("utf-8")
        output["returncode"] = proc.returncode
    except (subprocess.TimeoutExpired) as _:
        Print("ERROR: Nodeos is running beyond the defined wait time. Hard killing nodeos instance.")
        proc.send_signal(signal.SIGKILL)
        return (False, None)

    if debug: Print("Returning success.")
    return (True, output)

random.seed(seed) # Use a fixed seed for repeatability.
cluster=Cluster(walletd=True)

try:
    TestHelper.printSystemInfo("BEGIN")

    cluster.setChainStrategy(chainSyncStrategyStr)

    cluster.killall(allInstances=killAll)
    cluster.cleanup()

    Print ("producing nodes: %d, topology: %s, delay between nodes launch(seconds): %d, chain sync strategy: %s" % (
        pnodes, topo, delay, chainSyncStrategyStr))

    Print("Stand up cluster")
    if cluster.launch(pnodes=pnodes, totalNodes=total_nodes, topo=topo, delay=delay, dontBootstrap=True) is False:
        errorExit("Failed to stand up eos cluster.")

    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    Print("Kill the cluster.")
    for node in cluster.getNodes():
        node.kill(signal.SIGTERM)

    cluster.biosNode.kill(signal.SIGTERM)

    # `kill -9` nodeos and make sure it can start back
    Print("Restart nodeos then kill -9 it repeatedly, ensuring NO dirty database flag.")

    for i in range(3):
        Print("Attempt %d." % (i))

        Print("Start a nodeos and kill it with SIGKILL.")
        cluster.biosNode.relaunch(cachePopen=True)
        time.sleep(5)

        cluster.biosNode.kill(signal.SIGKILL)

        timeout=15
        ret = runNodeosAndGetOutput(timeout)

        assert(ret)
        assert(isinstance(ret, tuple))
        if not ret[0]:
            errorExit("Failed to startup nodeos successfully on try number %d" % (i))
        assert(ret[1])
        assert(isinstance(ret[1], dict))
        # pylint: disable=unsubscriptable-object
        stderr= ret[1]["stderr"]
        retCode=ret[1]["returncode"]
        expectedRetCode = 0
        if retCode != expectedRetCode:
            errorExit("Expected return code to be %d, but instead received %d. output={\n%s\n}" % (expectedRetCode, retCode, ret))
        db_dirty_msg="atabase dirty flag set"
        if db_dirty_msg in stderr:
            errorExit("stderr should NOT have contained \"%s\" but it did. stderr=\n%s" % (db_dirty_msg, stderr))

    if debug: Print("Setting test result to success.")
    testSuccessful=True
finally:
    if debug: Print("Cleanup in finally block.")
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

if debug: Print("Exiting test, exit value 0.")
exitCode = 0 if testSuccessful else 1
exit(exitCode)