#!/bin/sh

set -ef

CAPTURE="${abs_srcdir}/handshake-dual-path.pcap"

# PMKID-only path.
"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -b 02:00:00:00:00:02 \
    -e AuditPmkid \
    -q "${CAPTURE}" | \
        ${GREP} 'KEY FOUND! \[ 12345678 \]'

# Four-way handshake path from the same capture.
"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -b 02:00:00:00:00:03 \
    -e AuditFourway \
    -q "${CAPTURE}" | \
        ${GREP} 'KEY FOUND! \[ 12345678 \]'

exit 0
