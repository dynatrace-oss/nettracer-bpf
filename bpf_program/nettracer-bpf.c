/* This needs to be on the top.
 * Otherwise kernel headers won't compile.
 */
#include <linux/kconfig.h>
#include "asm_inline.h"
#define KBUILD_MODNAME "nettracer"

#include "maps.h"
#include "probes/connections.h"
#include "probes/metrics.h"
#include "probes/other.h"

#include "bpf_helpers.h"
#include <linux/version.h>

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = LINUX_VERSION_CODE;
