"""Starting from a UTXO snapshot (spec 6) over real sockets. Run from the repository root after
`cargo build --release` at the root (both crates):

    python3 node/tests/e2e_snapshot.py

1. node A mines 1,450 blocks; the block at 1,440 commits to the UTXO set after 1,439;
2. node D starts with --snapshot-sync: it gets the headers, block 1,440, the chunks of the set
   (each checked against that block's utxo_root), and then only the blocks after it;
3. D follows new blocks, survives a restart, and serves the snapshot to node E, which has
   no other peer.
"""
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402
from e2e import call, cli, start, stop, wait  # noqa: E402


def main():
    import json
    a0 = json.loads(cli('wallet', 'address', '--words', e2e.WORDS))['address']
    pa, _ = start('a')
    call('a', 'generate', 1450, a0)
    ia = call('a', 'getinfo')
    assert ia['snapshots'] == [1440], ia
    print('1. A mined %d blocks (%d outputs), snapshot at 1440' % (ia['height'], ia['utxos']))

    pd, _ = start('d', '--snapshot-sync', '--connect', '127.0.0.1:%d' % pa)
    wait('d at the tip', lambda: call('d', 'getinfo')['tip'] == ia['tip'], timeout=120)
    idd = call('d', 'getinfo')
    assert idd['base'] == 1439 and idd['supply'] == ia['supply'] and idd['utxos'] == ia['utxos'], idd
    try:
        call('d', 'getblock', '100')
        raise AssertionError('D should not have block 100')
    except RuntimeError as e:
        assert 'not stored' in str(e)
    print('2. D started from the snapshot: base %d, same tip, supply %s, no blocks below it' % (idd['base'], idd['supply']))

    call('a', 'generate', 5, a0)
    wait('d follows', lambda: call('d', 'getinfo')['tip'] == call('a', 'getinfo')['tip'])
    stop('d')
    start('d')
    idd = call('d', 'getinfo')
    assert idd['tip'] == call('a', 'getinfo')['tip'] and idd['base'] == 1439, idd
    start('e', '--snapshot-sync', '--connect', '127.0.0.1:%d' % e2e.procs['d'][1])
    wait('e at the tip', lambda: call('e', 'getinfo')['tip'] == idd['tip'], timeout=120)
    assert call('e', 'getinfo')['base'] == 1439
    print('3. D followed 5 new blocks, restarted at height %d, and E synced from D alone' % idd['height'])
    print('OK')


if __name__ == '__main__':
    try:
        main()
    finally:
        for p in [v[0] for v in e2e.procs.values()] + e2e.helpers:
            p.terminate()
        if os.environ.get('KEEP'):
            print('logs in', e2e.TMP)
        else:
            shutil.rmtree(e2e.TMP, ignore_errors=True)
