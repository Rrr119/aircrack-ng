#!/bin/sh

set -ef

# The first M2 has a bad MIC.  A later M1 starts a retry and the valid M2
# must replace the broken attempt for the same BSSID/client association.
"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -b 02:00:00:00:00:04 \
    -e AuditRetry \
    -q "${abs_srcdir}/handshake-retry.pcap" | \
        ${GREP} 'KEY FOUND! \[ 12345678 \]'

exit 0
