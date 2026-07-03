#!/bin/sh
# Wedged "tshark" stand-in for the ADR-0049 §Acceptance TIMEOUT bite-proof.
#
# The dispatcher (app.engines.packet.sandbox._spawn_and_reap) spawns the executor
# child in its own session (start_new_session=True) and SIGKILLs the WHOLE process
# group on timeout (blocker 4). The executor, in turn, spawns "tshark". This script
# stands in for that tshark: it records its own PID (the grandchild the group-kill
# must reap) to a fixed path on the writable tmpfs, then sleeps far past the
# dispatcher's timeout. If the process-group kill works, this PID is gone shortly
# after the timeout fires; if it leaks, an orphan survives and the driver fails.
#
# The PID path is FIXED (not env-derived): the executor forwards only a minimal env
# allowlist (PATH/TMPDIR/LANG/LC_*) to its child, so any custom var would be
# stripped. The driver reads this same fixed path.
set -eu
echo "$$" > /tmp/pyshark/grandchild.pid
exec sleep 600
