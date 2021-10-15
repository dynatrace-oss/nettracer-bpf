#include <optional>
#include <string>
#include <string_view>

struct utsname;

namespace bpf {

std::optional<int> getKernelVersion();

bool isKernelSupported(int kernelVersion);

std::string kernelVersionToString(int kernelVersion);

namespace detail {

std::optional<int> getKernelVersionOnUbuntu();
std::optional<int> getKernelVersionOnDebian(const utsname& info);
std::optional<int> getKernelVersionFromUname(const utsname& info);

utsname getUtsname();

std::optional<int> parseVersionFromString(std::string_view str);

} // namespace detail

} // namespace bpf
