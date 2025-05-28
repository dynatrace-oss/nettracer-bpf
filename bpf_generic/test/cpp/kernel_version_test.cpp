/*
* Copyright 2025 Dynatrace LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License cat
*
* https://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
#include <gtest/gtest.h>
#include "kernel_version.h"
#include "mock_system_calls.h"
#include <algorithm>
#include <linux/version.h>

using namespace std::string_literals;
using namespace bpf;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;
using testing::SetArrayArgument;

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

class GenericVersionTest : public testing::Test {
protected:
	GenericVersionTest() {
		// statically make sure that the utsname fields are 'reasonably' big
		// i.e. enough to fit values from tests
		// on different machines their sizes may differ (see https://man7.org/linux/man-pages/man2/uname.2.html)
		static_assert(sizeof(utsname::release) >= 65);
		static_assert(sizeof(utsname::version) >= 65);
	}

	void expectUname(const utsname& unameResult) const {
		EXPECT_CALL(sysCalls, uname)
			.WillOnce(DoAll(
				SetArgPointee<0>(unameResult),
				Return(0)));
	}

	void expectFailedUname() const {
		EXPECT_CALL(sysCalls, uname)
			.WillOnce(Return(-1));
	}

	void expectSignatureRead(std::string_view signature) const {
		std::FILE* dummyFile{reinterpret_cast<std::FILE*>(0x123456)};
		EXPECT_CALL(sysCalls, fopen)
			.WillOnce(Return(dummyFile));
		EXPECT_CALL(sysCalls, fread)
			.WillOnce(DoAll(
				SetArrayArgument<0>(signature.cbegin(), signature.cend()),
				Return(signature.size())));
		EXPECT_CALL(sysCalls, fclose)
			.WillOnce(Return());
	}

	void expectFailedSignatureRead() const {
		EXPECT_CALL(sysCalls, fopen)
			.WillOnce(Return(nullptr));
	}

	void checkParsedVersion(int expMajor, int expMinor, int expPatch) const {
		auto parsed{getKernelVersion(sysCalls)};
		ASSERT_TRUE(parsed);
		EXPECT_EQ(*parsed, KERNEL_VERSION(expMajor, expMinor, expPatch));
	}

	void checkFailedParse() const {
		auto parsed{getKernelVersion(sysCalls)};
		ASSERT_FALSE(parsed);
	}

	MockSystemCalls sysCalls;
};

class VersionOnUbuntuTest : public GenericVersionTest {
public:
	void checkParsedVersion(std::string_view signature, int expMajor, int expMinor, int expPatch) const {
		expectUname(ubuntuUnameResult);
		expectSignatureRead(signature);
		GenericVersionTest::checkParsedVersion(expMajor, expMinor, expPatch);
	}

	void checkFailedParseBadSignature(std::string_view signature) const {
		expectUname(ubuntuUnameResult);
		expectSignatureRead(signature);
		GenericVersionTest::checkFailedParse();
	}

	void checkFailedParseSignatureMissing() const {
		expectUname(ubuntuUnameResult);
		expectFailedSignatureRead();
		GenericVersionTest::checkFailedParse();
	}

private:
	// it's only important to have Ubuntu somewhere in version
	const utsname ubuntuUnameResult{"Linux", "hostname", "Ubuntu 4.19.0", "Ubuntu 4.15.0-21", "x86_64"};
};

TEST_F(VersionOnUbuntuTest, test_proper_version_at_end) {
	checkParsedVersion("Ubuntu 5.4.0-80.90~18.04.1-generic 5.4.124", 5, 4, 124);
}

TEST_F(VersionOnUbuntuTest, test_shorter_version_but_ok) {
	checkParsedVersion("5.4.0 5.4.128-67", 5, 4, 128);
}

TEST_F(VersionOnUbuntuTest, test_only_one_version_but_ok) {
	checkParsedVersion("Ubuntu 5.4.0-80.90", 5, 4, 0);
}

TEST_F(VersionOnUbuntuTest, test_invalid_signature) {
	checkFailedParseBadSignature("5.4.0.1");
}

TEST_F(VersionOnUbuntuTest, test_empty_signature) {
	checkFailedParseBadSignature("");
}

TEST_F(VersionOnUbuntuTest, test_signature_file_missing) {
	checkFailedParseSignatureMissing();
}

class VersionOnDebianTest : public GenericVersionTest {
public:
	void checkParsedVersion(std::string_view version, int expMajor, int expMinor, int expPatch) const {
		utsname unameResult{debianBasicUnameResult};
		std::copy(version.cbegin(), version.cend(), std::begin(unameResult.version));
		expectUname(unameResult);
		GenericVersionTest::checkParsedVersion(expMajor, expMinor, expPatch);
	}

	void checkFailedParse(std::string_view version) const {
		utsname unameResult{debianBasicUnameResult};
		std::copy(version.cbegin(), version.cend(), std::begin(unameResult.version));
		expectUname(unameResult);
		GenericVersionTest::checkFailedParse();
	}

private:
	const utsname debianBasicUnameResult{"Linux", "node", "4.19.0-18-amd64", "", "x86_64"};
};

TEST_F(VersionOnDebianTest, test_debian_release) {
	checkParsedVersion("#1 SMP Debian 4.19.208-1 (2021-09-29)", 4, 19, 208);
}

TEST_F(VersionOnDebianTest, test_version_missing) {
	checkFailedParse("#1 SMP Debian (2021-09-29)");
}

class VersionOnGenericDistroTest : public GenericVersionTest {
public:
	void checkParsedVersion(std::string_view release, int expMajor, int expMinor, int expPatch) const {
		utsname unameRet{"Linux", "node", "", "#1 SMP Tue Jun 1 16:14:33 UTC 2021", "x86_64"};
		std::copy(release.cbegin(), release.cend(), std::begin(unameRet.release));
		expectUname(unameRet);
		GenericVersionTest::checkParsedVersion(expMajor, expMinor, expPatch);
	}

	void checkFailedParse(std::string_view release) const {
		utsname unameRet{"Linux", "node", "", "#1 SMP Tue Jun 1 16:14:33 UTC 2021", "x86_64"};
		std::copy(release.cbegin(), release.cend(), std::begin(unameRet.release));
		expectUname(unameRet);
		GenericVersionTest::checkFailedParse();
	}
};

TEST_F(VersionOnGenericDistroTest, test_empty_fail) {
	checkFailedParse("");
}

TEST_F(VersionOnGenericDistroTest, test_wrong_string_fail) {
	checkFailedParse("Debian");
}

TEST_F(VersionOnGenericDistroTest, test_gibberish_fail) {
	checkFailedParse("a.bb.c");
}

TEST_F(VersionOnGenericDistroTest, test_too_short_fail) {
	checkFailedParse("4.19");
}

TEST_F(VersionOnGenericDistroTest, test_too_long_fail) {
	checkFailedParse("5.4.0.124");
}

TEST_F(VersionOnGenericDistroTest, test_uname_failed) {
	GenericVersionTest::expectFailedUname();
	EXPECT_THROW({ getKernelVersion(sysCalls); }, std::runtime_error);
}

TEST_F(VersionOnGenericDistroTest, test_5_4_0_simple) {
	checkParsedVersion("5.4.0", 5, 4, 0);
}

TEST_F(VersionOnGenericDistroTest, test_5_4_0_inside) {
	checkParsedVersion("Linux 5.4.0 x64", 5, 4, 0);
}

TEST_F(VersionOnGenericDistroTest, test_4_17_2_dash) {
	checkParsedVersion("Linux 4.17.2-123", 4, 17, 2);
}

TEST_F(VersionOnGenericDistroTest, test_centos_similar_candidate) {
	checkParsedVersion("4.18.0-305.3.1.el8.x86_64", 4, 18, 0);
}
