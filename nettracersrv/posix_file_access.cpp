#include <unistd.h>
#include "posix_file_access.h"

std::unique_ptr<IFileAccessChecker> IFileAccessChecker::create() {
	return std::make_unique<PosixFileAccessChecker>();
}

bool PosixFileAccessChecker::hasAccess(const std::filesystem::path& path, const AccessMode mode) const noexcept {

	try {
		const auto posixMode = toPosixMode(mode);
		return ::access(path.c_str(), posixMode) == 0;
	} catch (const std::invalid_argument&) {
		return false;
	}
}

int PosixFileAccessChecker::toPosixMode(AccessMode mode){
	switch (mode){
	case AccessMode::Exists:	return F_OK;
	case AccessMode::Read:		return R_OK;
	case AccessMode::Write:		return W_OK;
	case AccessMode::ReadWrite: return R_OK | W_OK;
	case AccessMode::Execute:	return X_OK;
	}
	throw std::invalid_argument("Unsupported Access Mode");
}