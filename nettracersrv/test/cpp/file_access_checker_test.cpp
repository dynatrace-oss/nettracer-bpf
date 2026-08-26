#include "file_access_interface.h"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <unistd.h>

namespace fs = std::filesystem;

class FileAccessCheckerTest : public ::testing::Test {
protected:
	void SetUp() override {
		testDir = fs::temp_directory_path() / "file_access_checker_tests";
		fs::create_directories(testDir);

		existingFile = testDir / "test_file.txt";
		nonExistingFile = testDir / "ghost_file.txt";

		std::ofstream ofs(existingFile);
		ofs << "Hello GTest";
		ofs.close();

		checker = IFileAccessChecker::create();
	}

	void TearDown() override {
		std::error_code ec;
		fs::permissions(testDir, fs::perms::owner_all, fs::perm_options::add, ec);
		fs::remove_all(testDir, ec); 
	}

	fs::path testDir;
	fs::path existingFile;
	fs::path nonExistingFile;
	std::unique_ptr<IFileAccessChecker> checker;
};

//	EXISTENCE TESTS (F_OK)
TEST_F(FileAccessCheckerTest, FileExistsShouldReturnTrue) {
	EXPECT_TRUE(checker->hasAccess(existingFile, AccessMode::Exists));
}

TEST_F(FileAccessCheckerTest, NonExistingFileShouldReturnFalseForExists) {
	EXPECT_FALSE(checker->hasAccess(nonExistingFile, AccessMode::Exists));
}

//	READING TESTS (R_OK)
TEST_F(FileAccessCheckerTest, RegularFileShouldBeReadable) {
	EXPECT_TRUE(checker->hasAccess(existingFile, AccessMode::Read));
}

TEST_F(FileAccessCheckerTest, NonExistingFileShouldNotBeReadable) {
	EXPECT_FALSE(checker->hasAccess(nonExistingFile, AccessMode::Read));
}

//	WRITE TESTS (W_OK)
TEST_F(FileAccessCheckerTest, RegularFileInTempDirShouldBeWritable) {
	EXPECT_TRUE(checker->hasAccess(existingFile, AccessMode::Write));
	EXPECT_TRUE(checker->hasAccess(existingFile, AccessMode::ReadWrite));
}

TEST_F(FileAccessCheckerTest, ProtectedFileShouldReturnFalseForWrite) {
	fs::path protectedFile = testDir / "protected.txt";
	std::ofstream(protectedFile).close();
	fs::permissions(protectedFile, fs::perms::owner_read, fs::perm_options::replace);

	if (::getuid() != 0) {
		EXPECT_TRUE(checker->hasAccess(protectedFile, AccessMode::Read));
		EXPECT_FALSE(checker->hasAccess(protectedFile, AccessMode::Write));
	}
}

//	COMPOUND TESTS (R_OK | W_OK)
TEST_F(FileAccessCheckerTest, RegularFileShouldBeReadWritable) {
	EXPECT_TRUE(checker->hasAccess(existingFile, AccessMode::ReadWrite));
}

TEST_F(FileAccessCheckerTest, ReadOnlyFileShouldReturnFalseForReadWrite) {
	fs::path readOnlyFile = testDir / "readonly.txt";
	std::ofstream(readOnlyFile).close();
	fs::permissions(readOnlyFile, fs::perms::owner_read, fs::perm_options::replace);

	if (::getuid() != 0) {
		EXPECT_FALSE(checker->hasAccess(readOnlyFile, AccessMode::ReadWrite));
	}
}

// EXECUTION TESTS (X_OK)
TEST_F(FileAccessCheckerTest, ExecutableFileShouldReturnTrueForExecute) {
	fs::path execFile = testDir / "exec_file.sh";
	std::ofstream(execFile).close();
	fs::permissions(execFile, fs::perms::owner_exec, fs::perm_options::replace);

	EXPECT_TRUE(checker->hasAccess(execFile, AccessMode::Execute));
}

TEST_F(FileAccessCheckerTest, NonExecutableFileShouldReturnFalseForExecute) {
	fs::permissions(existingFile, fs::perms::none, fs::perm_options::replace);

	if (::getuid() != 0) {
		EXPECT_FALSE(checker->hasAccess(existingFile, AccessMode::Execute));
	}
}

//  EDGE CASE TESTS AND ERRORS
TEST_F(FileAccessCheckerTest, EmptyPathShouldReturnFalse) {
	EXPECT_FALSE(checker->hasAccess(fs::path(""), AccessMode::Exists));
}

TEST_F(FileAccessCheckerTest, InvalidEnumModeShouldBeCaughtAndReturnFalse) {
	auto corruptedMode = static_cast<AccessMode>(99);
	EXPECT_FALSE(checker->hasAccess(existingFile, corruptedMode));
}