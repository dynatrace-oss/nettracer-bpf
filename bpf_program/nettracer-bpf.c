/* This needs to be on the top.
 * Otherwise kernel headers won't compile.
 */

#ifdef LEGACY_BPF
#include <linux/kconfig.h>
#include "asm_inline.h"
#include <linux/version.h>
#include "legacy/maps.h"
#include "legacy/other.h"
#else
#include "maps.h"
#endif

#include "probes/connections.h"
#include "probes/metrics.h"

#define KBUILD_MODNAME "nettracer"

char _license[] SEC("license") = "GPL";
#ifdef LEGACY_BPF
uint32_t _version SEC("version") = LINUX_VERSION_CODE;
#endif
