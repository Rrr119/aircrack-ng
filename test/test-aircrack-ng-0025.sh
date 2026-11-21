#!/bin/sh

set -ef

# Two clients are associated with the same BSSID.  The first client only has
# M1; the complete handshake from the second client must be selected.
"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -b 02:00:00:00:00:01 \
    -e AuditAgg \
    -q "${abs_srcdir}/handshake-aggregate.pcap" | \
        ${GREP} 'KEY FOUND! \[ 12345678 \]'

exit 0
