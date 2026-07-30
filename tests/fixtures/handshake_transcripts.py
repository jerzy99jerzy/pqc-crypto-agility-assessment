"""Synthetic `openssl s_client` transcripts for parser testing.

PROVENANCE: these are hand-written approximations of OpenSSL 3.5 s_client
output, constructed to exercise parse_handshake_output. They are NOT captured
from a live handshake. No claim in this file is [measured]; every string here
is a test fixture. They must never be treated as evidence that any host does or
does not negotiate a hybrid group.

The shapes mirror the fields the parser looks for: "Negotiated TLS1.3 group",
"Protocol", "Cipher", "Server Temp Key", and the "write client hello" state
lines whose count betrays a HelloRetryRequest.
"""

# Hybrid group negotiated in a single round trip.
HYBRID_SINGLE_RT = """\
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
SSL_connect:TLSv1.3 read encrypted extensions
Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Server Temp Key: X25519MLKEM768, 1216 bits
Negotiated TLS1.3 group: X25519MLKEM768
Verification: OK
DONE
"""

# Server forces a HelloRetryRequest: the client writes ClientHello a second
# time, then the hybrid group is negotiated.
HYBRID_WITH_HRR = """\
CONNECTED(00000003)
SSL_connect:before SSL initialization
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read hello retry request
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
Protocol: TLSv1.3
Cipher: TLS_AES_128_GCM_SHA256
Server Temp Key: X25519MLKEM768, 1216 bits
Negotiated TLS1.3 group: X25519MLKEM768
Verification: OK
DONE
"""

# Server does not support the hybrid group and falls back to classical X25519.
CLASSICAL_FALLBACK = """\
CONNECTED(00000003)
SSL_connect:SSLv3/TLS write client hello
SSL_connect:SSLv3/TLS read server hello
Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Server Temp Key: X25519, 253 bits
Negotiated TLS1.3 group: X25519
Verification: OK
DONE
"""

# A build/sensor that lacks a name for the codepoint reports it numerically.
HYBRID_CODEPOINT_ONLY = """\
CONNECTED(00000003)
SSL_connect:SSLv3/TLS write client hello
Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Negotiated TLS1.3 group: SecP256r1MLKEM768
Verification: OK
DONE
"""

# Connection refused: no handshake fields at all, non-zero return code.
CONNECT_FAILURE = """\
CONNECTED(00000003)
connect:errno=111
"""

# Timeout path emits nothing; probe() supplies returncode -1 and an empty blob.
EMPTY_BLOB = ""
