# Drivechain tools


get thunder deposit address:
    ui: https://github.com/LayerTwo-Labs/drivechain-frontends/blob/d85df256ddb4a4b5ae0f49f946f6442526700833/bitwindow/lib/pages/sidechains_page.dart#L1693
    ui rpc: https://github.com/LayerTwo-Labs/drivechain-frontends/blob/d85df256ddb4a4b5ae0f49f946f6442526700833/bitwindow/lib/pages/sidechains_page.dart#L1594
    rpc getNewAddress: https://github.com/LayerTwo-Labs/drivechain-frontends/blob/d85df256ddb4a4b5ae0f49f946f6442526700833/sail_ui/lib/rpcs/thunder_rpc.dart#L132
        thunder server rpc get_new_address: https://github.com/LayerTwo-Labs/thunder-rust/blob/master/app/rpc_server.rs#L142
        thunder actual logic: https://github.com/LayerTwo-Labs/thunder-rust/blob/master/lib/wallet.rs#L491
        formataddress s9_xxx_xxx: https://github.com/LayerTwo-Labs/drivechain-frontends/blob/d85df256ddb4a4b5ae0f49f946f6442526700833/sail_ui/lib/bitcoin.dart#L72
    or in the console:
        get-wallet-addresses
        format-deposit-address <pick one address from above>

perform sidechain deposit:
    ui which does rpc: https://github.com/LayerTwo-Labs/drivechain-frontends/blob/d85df256ddb4a4b5ae0f49f946f6442526700833/bitwindow/lib/pages/sidechains_page.dart#L1611
    bitwindow rpc server: https://github.com/LayerTwo-Labs/drivechain-frontends/blob/d85df256ddb4a4b5ae0f49f946f6442526700833/bitwindow/server/api/wallet/wallet.go#L1155
    enforcer rpc: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/b7cc835422496a2a5d456048da28c3fb99423243/lib/server/wallet/grpc.rs#L493
    wallet create_deposit: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/master/lib/wallet/mod.rs#L1364



database logic:
    bdk_anchors:
        when enforcer gets a new block: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/a4197ad2ae9d35252d12008ff616bce710b647d2/lib/wallet/sync.rs#L57
        bdk_wallet calls apply_block: https://github.com/bitcoindevkit/bdk_wallet/blob/d8e006f0b2fbac5ae56e84990fbeab6337c160e3/src/wallet/mod.rs#L2459
        bdk calls apply_block_relevant: https://github.com/bitcoindevkit/bdk/blob/47556ab7094c6af5c500eda9c9fa43f6d1804563/crates/chain/src/indexed_tx_graph.rs#L370
        bdk insert_anchor: https://github.com/bitcoindevkit/bdk/blob/master/crates/chain/src/tx_graph.rs#L745
    bdk_txs first_seen, last_seen:
        enforcer send_wallet_transaction: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/master/lib/wallet/mod.rs#L1791
        bdk_wallet apply_unconfirmed_txs: https://github.com/bitcoindevkit/bdk_wallet/blob/d8e006f0b2fbac5ae56e84990fbeab6337c160e3/src/wallet/mod.rs#L2506
        bdk batch_insert_unconfirmed: https://github.com/bitcoindevkit/bdk/blob/47556ab7094c6af5c500eda9c9fa43f6d1804563/crates/chain/src/tx_graph.rs#L728
        bdk insert_seen_at, which modifies both first_seen and last_seen: https://github.com/bitcoindevkit/bdk/blob/47556ab7094c6af5c500eda9c9fa43f6d1804563/crates/chain/src/tx_graph.rs#L728
    bdk_txs last_evicted:
        enforcer connect_block: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/a4197ad2ae9d35252d12008ff616bce710b647d2/lib/wallet/cusf_block_producer.rs#L202
        bdk_wallet apply_evicted_txs: https://github.com/bitcoindevkit/bdk_wallet/blob/d8e006f0b2fbac5ae56e84990fbeab6337c160e3/src/wallet/mod.rs#L2573
        bdk batch_insert_relevant_evicted_at: https://github.com/bitcoindevkit/bdk/blob/master/crates/chain/src/indexed_tx_graph.rs#L239C12-L239C44
        bdk insert_evicted_at: https://github.com/bitcoindevkit/bdk/blob/master/crates/chain/src/tx_graph.rs#L868C12-L868C29


electrum:
    esplora: https://github.com/Blockstream/electrs/
    original electrum uses rpc api: https://github.com/spesmilo/electrum-server/blob/master/src/blockchain_processor.py#L646


wallet restoration:
    bdk_wallet official way of restoration: https://github.com/bitcoindevkit/bdk_wallet/blob/b5db35ecf58bf72026d4063ec759ed6e7e8a70af/examples/esplora_blocking.rs#L62
        retrieves transactions of a scriptPubKey: https://github.com/bitcoindevkit/bdk/blob/47556ab7094c6af5c500eda9c9fa43f6d1804563/crates/esplora/src/blocking_ext.rs#L306
        client: https://github.com/bitcoindevkit/rust-esplora-client/blob/f95aa6c258fed252c2c18fafe132e890c2838587/src/blocking.rs#L436
        server: https://github.com/Blockstream/electrs/blob/503b740cce2133fd07f451cbe93249a4e092b300/src/rest.rs#L839
    enforcer way of restoration: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/7c98d4431dc4dc94c940685cb24d75e2e9454981/lib/wallet/sync.rs#L262


wallet loading:
    enforcer L1: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/cbc1f8020cf81744b68bb52bc280a1ca385223f8/lib/wallet/mod.rs#L296
    bkd_wallet params load: https://github.com/bitcoindevkit/bdk_wallet/blob/39de6ed387af67b23a37c874edd0cd4f1daf8044/src/wallet/params.rs#L346
    bkd_wallet wallet load: https://github.com/bitcoindevkit/bdk_wallet/blob/master/src/wallet/persisted.rs#L234
        get changeset:
            bdk_wallet initialize flow: https://github.com/bitcoindevkit/bdk_wallet/blob/master/src/wallet/persisted.rs#L286 then https://github.com/bitcoindevkit/bdk_wallet/blob/master/src/wallet/persisted.rs#L272
            bdk_wallet initiailize actual from_sqlite: https://github.com/bitcoindevkit/bdk_wallet/blob/master/src/wallet/changeset.rs#L250
        load_with_params: https://github.com/bitcoindevkit/bdk_wallet/blob/master/src/wallet/mod.rs#L433
            make_indexed_graph: https://github.com/bitcoindevkit/bdk_wallet/blob/master/src/wallet/mod.rs#L2837
                make_indexed_graph function signature specifies that IndexedTxGraph generic is IndexedTxGraph<\_, KeychainTxOutIndex>, which means IndexedTxGraph.index is of type KeychainTxOutIndex: https://github.com/bitcoindevkit/bdk/blob/master/crates/chain/src/indexed_tx_graph.rs#L20
                IndexedTxGraph::from_changeset: https://github.com/bitcoindevkit/bdk/blob/47556ab7094c6af5c500eda9c9fa43f6d1804563/crates/chain/src/indexed_tx_graph.rs#L133
                    KeychainTxOutIndex::from_changeset: https://github.com/bitcoindevkit/bdk/blob/47556ab7094c6af5c500eda9c9fa43f6d1804563/crates/chain/src/indexer/keychain_txout.rs#L259
                        apply_changeset sets last_revealed which is the number of addresses created by a descriptor: https://github.com/bitcoindevkit/bdk/blob/47556ab7094c6af5c500eda9c9fa43f6d1804563/crates/chain/src/indexer/keychain_txout.rs#L965
                    IndexedTxGraph."reindex", this eventually sets spk_txouts, which is {script_public_key_index, outpoint{transaction_id, transaction_output_index}}: https://github.com/bitcoindevkit/bdk/blob/master/crates/chain/src/indexed_tx_graph.rs#L152
                    "reindex" calls self.index.index_txout which is KeychainTxOutIndex.index_txout: https://github.com/bitcoindevkit/bdk/blob/47556ab7094c6af5c500eda9c9fa43f6d1804563/crates/chain/src/indexer/keychain_txout.rs#L161
                    KeychainTxOutIndex.index_txout calls \_index_txout: https://github.com/bitcoindevkit/bdk/blob/47556ab7094c6af5c500eda9c9fa43f6d1804563/crates/chain/src/indexer/keychain_txout.rs#L265
                    KeychainTxOutIndex.\_index_txout eventually calls KeychainTxOutIndex.inner.scan_txout, where KeychainTxOutIndex.inner is of type SpkTxOutIndex: https://github.com/bitcoindevkit/bdk/blob/47556ab7094c6af5c500eda9c9fa43f6d1804563/crates/chain/src/indexer/keychain_txout.rs#L130
                    SpkTxOutIndex.scan_txout inserts into SpkTxOutIndex.spk_txouts: https://github.com/bitcoindevkit/bdk/blob/master/crates/chain/src/indexer/spk_txout.rs#L112
            bdk_wallet wallet.tx_graph is of type IndexedTxGraph: https://github.com/bitcoindevkit/bdk_wallet/blob/master/src/wallet/mod.rs#L579
    wallet.list_unspent returns the L1 utxos: https://github.com/bitcoindevkit/bdk_wallet/blob/master/src/wallet/mod.rs#L780
        calls filter_chain_txouts: https://github.com/bitcoindevkit/bdk/blob/faf520d61a647a5dcba74e3aa681919349f4dfe4/crates/chain/src/tx_graph.rs#L1109
        list_unspent calls wallet.tx_graph.index.outpoints, and wallet.tx_graph.index is of type wallet.IndexedTxGraph.KeychainTxOutIndex, which means this calls KeychainTxOutIndex.outpoints: https://github.com/bitcoindevkit/bdk/blob/47556ab7094c6af5c500eda9c9fa43f6d1804563/crates/chain/src/indexer/keychain_txout.rs#L312
        KeychainTxOutIndex.outpoints calls KeychainTxOutIndex.inner.outpoints which is KeychainTxOutIndex.SpkTxOutIndex.outpoints which is SpkTxOutIndex.spk_txouts. Note that SpkTxOutIndex.spk_txouts is being prepared during wallet loading: https://github.com/bitcoindevkit/bdk/blob/master/crates/chain/src/indexer/spk_txout.rs#L123
    


how to get L1 address:
    wallet.json: https://github.com/LayerTwo-Labs/drivechain-frontends/blob/master/sidechain-orchestrator/wallet/keygen.go
    ui: https://github.com/LayerTwo-Labs/drivechain-frontends/blob/70bf76da2a5a624e41cec45b3b6c1852355f9503/bitwindow/lib/pages/wallet/wallet_receive.dart#L38
    then goes to singleton: https://github.com/LayerTwo-Labs/drivechain-frontends/blob/70bf76da2a5a624e41cec45b3b6c1852355f9503/bitwindow/lib/providers/transactions_provider.dart#L21
    then does rpc: https://github.com/LayerTwo-Labs/drivechain-frontends/blob/70bf76da2a5a624e41cec45b3b6c1852355f9503/sail_ui/lib/rpcs/orchestrator_wallet_rpc.dart#L16https://github.com/LayerTwo-Labs/drivechain-frontends/blob/70bf76da2a5a624e41cec45b3b6c1852355f9503/sail_ui/lib/rpcs/orchestrator_wallet_rpc.dart#L16
    rpc go server: https://github.com/LayerTwo-Labs/drivechain-frontends/blob/70bf76da2a5a624e41cec45b3b6c1852355f9503/sidechain-orchestrator/api/wallet_handler.go#L352
    rpc to rust enforcer: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/f5da80ddb79b677e9d80ea2fec8e6c990523d48d/lib/server/wallet/grpc.rs#L215
    enforcer logic: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/master/lib/wallet/mod.rs#L2132
    enforcer uses bdk_wallet: https://github.com/bitcoindevkit/bdk_wallet/blob/39de6ed387af67b23a37c874edd0cd4f1daf8044/src/wallet/mod.rs#L709


descriptor checksum:
    write db: https://github.com/bitcoindevkit/bdk_wallet/blob/master/src/wallet/changeset.rs#L318
    fmt for wpkh: https://github.com/rust-bitcoin/rust-miniscript/blob/bdf50e3bad8130989fde5a014ea6c0306a7e36cf/src/descriptor/segwitv0.rs#L377
    write_descriptor macro: https://github.com/rust-bitcoin/rust-miniscript/blob/bdf50e3bad8130989fde5a014ea6c0306a7e36cf/src/descriptor/mod.rs#L1205
    write_wpkh() and input checksum engine: https://github.com/rust-bitcoin/rust-miniscript/blob/bdf50e3bad8130989fde5a014ea6c0306a7e36cf/src/descriptor/checksum.rs#L255
    write_checksum plus the "#": https://github.com/rust-bitcoin/rust-miniscript/blob/bdf50e3bad8130989fde5a014ea6c0306a7e36cf/src/descriptor/checksum.rs#L244
    checksum iter, input_fe->residue: https://github.com/rust-bitcoin/rust-miniscript/blob/bdf50e3bad8130989fde5a014ea6c0306a7e36cf/src/descriptor/checksum.rs#L180

how to get peers:
	bitwindow
		addnode: https://github.com/search?q=repo%3ALayerTwo-Labs%2Fdrivechain-frontends%20addnode&type=code
		UI to list peers: https://github.com/search?q=repo%3ALayerTwo-Labs/drivechain-frontends%20getPeerInfo&type=code
	bitcoind
		receivee ADDR message: https://github.com/drivechain-forknet/drivechain-forknet/blob/bb8a60eed93c2d8c8758ae42e144649ed205d516/src/net_processing.cpp#L4114
		actually adding to address map: https://github.com/drivechain-forknet/drivechain-forknet/blob/bb8a60eed93c2d8c8758ae42e144649ed205d516/src/addrman.cpp#L550
		actually listing addresses:
			code: https://github.com/drivechain-forknet/drivechain-forknet/blob/forknet-31/src/addrman.cpp#L812
			used in peer GETADDR message: https://github.com/drivechain-forknet/drivechain-forknet/blob/bb8a60eed93c2d8c8758ae42e144649ed205d516/src/net_processing.cpp#L4930
			used in cli: https://github.com/drivechain-forknet/drivechain-forknet/blob/bb8a60eed93c2d8c8758ae42e144649ed205d516/src/rpc/net.cpp#L956
