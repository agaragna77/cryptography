/* Probe for BoringSSL ML-DSA support (binary or source distribution).
 * If this file compiles, the BoringSSL install has include/openssl/mldsa.h
 * and thus supports ML-DSA (0.20251124.0 or later). */
#include <openssl/mldsa.h>

void probe_mldsa(void)
{
    (void)0;
}
