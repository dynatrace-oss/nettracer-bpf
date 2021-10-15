#include <gtest/gtest.h>
#include "kernel_version.h"
#include <linux/version.h>
#include <sys/utsname.h>

using namespace std::string_literals;
using namespace bpf;
using namespace detail;

class SupportedVersionTest : public testing::Test {
public:
	void checkSupported(int major, int minor, int patch, bool expectedSupported) {
		EXPECT_EQ(isKernelSupported(KERNEL_VERSION(major, minor, patch)), expectedSupported);
	}
};

TEST_F(SupportedVersionTest, test_5_4_supported) {
	checkSupported(5, 4, 0, true);
}

TEST_F(SupportedVersionTest, test_4_19_supported) {
	checkSupported(4, 19, 2, true);
}

TEST_F(SupportedVersionTest, test_4_15_supported) {
	checkSupported(4, 15, 0, true);
}

TEST_F(SupportedVersionTest, test_4_0_not_supported) {
	checkSupported(4, 0, 0, false);
}

TEST_F(SupportedVersionTest, test_3_12_not_supported) {
	checkSupported(3, 12, 0, false);
}

class VersionToStringTest : public testing::Test {
public:
	void checkString(int major, int minor, int patch, const std::string& expectedString) {
		EXPECT_EQ(kernelVersionToString(KERNEL_VERSION(major, minor, patch)), expectedString);
	}
};

TEST_F(VersionToStringTest, test_5_2_0_string) {
	checkString(5, 2, 0, "5.2.0"s);
}

TEST_F(VersionToStringTest, test_4_17_1_string) {
	checkString(4, 17, 1, "4.17.1"s);
}

class VersionFromStringTest : public testing::Test {
public:
	void checkParsedVersion(std::string_view str, int expMajor, int expMinor, int expPatch) {
		auto parsed{parseVersionFromString(str)};
		ASSERT_TRUE(parsed);
		EXPECT_EQ(*parsed, KERNEL_VERSION(expMajor, expMinor, expPatch));
	}
	void checkFailedParse(std::string_view str) {
		EXPECT_FALSE(parseVersionFromString(str));
	}
};

TEST_F(VersionFromStringTest, test_empty_fail) {
	checkFailedParse("");
}

TEST_F(VersionFromStringTest, test_wrong_string_fail) {
	checkFailedParse("Debian");
}

TEST_F(VersionFromStringTest, test_gibberish_fail) {
	checkFailedParse("a.bb.c");
}

TEST_F(VersionFromStringTest, test_too_short_fail) {
	checkFailedParse("4.19");
}

TEST_F(VersionFromStringTest, test_too_long_fail) {
	checkFailedParse("5.4.0.124");
}

TEST_F(VersionFromStringTest, test_5_4_0_simple) {
	checkParsedVersion("5.4.0", 5, 4, 0);
}

TEST_F(VersionFromStringTest, test_5_4_0_inside) {
	checkParsedVersion("Ubuntu 5.4.0 x64", 5, 4, 0);
}

TEST_F(VersionFromStringTest, test_4_17_2_dash) {
	checkParsedVersion("Ubuntu 4.17.2-123", 4, 17, 2);
}

TEST_F(VersionFromStringTest, test_ubuntu_proper_version_at_end) {
	checkParsedVersion("Ubuntu 5.4.0-80.90~18.04.1-generic 5.4.124", 5, 4, 124);
}

TEST_F(VersionFromStringTest, test_centos_similar_candidate) {
	checkParsedVersion("4.18.0-305.3.1.el8.x86_64", 4, 18, 0);
}

TEST_F(VersionFromStringTest, test_debian_release) {
	checkParsedVersion("#1 SMP Debian 4.19.208-1 (2021-09-29)", 4, 19, 208);
}

class VersionFindingTest : public testing::Test {
public:
	void checkFoundOnDebian(const utsname& info, int expMajor, int expMinor, int expPatch) {
		auto parsedVersion{getKernelVersionOnDebian(info)};
		ASSERT_TRUE(parsedVersion);
		EXPECT_EQ(*parsedVersion, KERNEL_VERSION(expMajor, expMinor, expPatch));
	}

	void checkFoundFromUname(const utsname& info, int expMajor, int expMinor, int expPatch) {
		auto parsedVersion{getKernelVersionFromUname(info)};
		ASSERT_TRUE(parsedVersion);
		EXPECT_EQ(*parsedVersion, KERNEL_VERSION(expMajor, expMinor, expPatch));
	}
};

TEST_F(VersionFindingTest, test_debian_10) {
	utsname info{"Linux", "my-node", "4.19.0-18-amd64", "#1 SMP Debian 4.19.208-1 (2021-09-29)", "x86_64"};
	checkFoundOnDebian(info, 4, 19, 208);
}

TEST_F(VersionFindingTest, test_centos_8_4) {
	utsname info{"Linux", "node-01", "4.18.0-305.3.1.el8.x86_64", "#1 SMP Tue Jun 1 16:14:33 UTC 2021", "x86_64"};
	checkFoundFromUname(info, 4, 18, 0);
}
