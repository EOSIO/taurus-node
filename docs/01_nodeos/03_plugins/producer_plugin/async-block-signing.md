## Description

The asynchronous block signing allows the EOSIO-Taurus to use a TPM device for signing for blocks to enhance the security, yet without affecting the block producing performance.

Within nodeos, the producer_plugin plays a crucial role in determining the appropriate signature(s) to utilize and facilitate the invocation of the corresponding signature providers. When employing TPM signature providers, the latency for block signing can range from approximately 30 to 60 milliseconds per block. To effectively utilize a TPM signature provider in nodeos, it may be necessary to enhance the system by implementing request threading to the TPM library. This enhancement would allow the main thread to handle other tasks concurrently, potentially mitigating any negative impact on the transaction throughput per second. Without this enhancement, a significant portion (around 6-12%) of the 500ms block time in nodeos would be wasted as the main thread idles awaiting the TPM signature.

A notable update in the chain's controller_impl involves the incorporation of an additional named_thread_pool exclusively dedicated to block signing. This thread pool is initialized with a single thread and promptly shut down during the destruction of controller_impl, right after the existing thread pool is stopped.

Previously, block signing was integrated into the block construction process. However, in the current design, block signing and block construction occur in separate threads. Block signing takes place after the completion of block construction. To enable the chain to advance the head block while block signing transpires in a separate thread, a new block_state is created with an empty signature. Subsequently, the head block progresses to this new state. In an effort to gracefully handle temporary signing failures, the controller salvages transactions from an unsigned head block that could not be signed and returns them to the applied transactions queue. The controller emits the accepted block signal only after the signing process is complete, and the irreversible blocks are logged.

To prevent any corruption of block log and index files, the controller performs a check on the status of the head block during shutdown. If the head block remains unsigned, the controller will abort the process and discard the block to maintain data integrity.

With the implementation of threaded signing, it is possible for the head block to be incomplete due to timing issues (signing has not had sufficient time to complete) or failures (signing returned an error). To address this, the fork database provides a remove_head() method to discard the incomplete head block.