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
#include "mock_bpf_maps.h"

// BPF maps wrapper mock is non-trivial, that's why some tests are needed also for it

class MockBPFMapsWrapperTest : public testing::Test {
protected:
	MockBPFMapsWrapperTest() : mockMap(mockMapsWrapper.createMap<int, bool>(mockMapFD)) {}

	void TearDown() override {
		mockMapsWrapper.clearMapsContents();
	}

	MockBPFMapsWrapper mockMapsWrapper;
	int mockMapFD{42};
	std::unordered_map<int, bool>& mockMap;
};

TEST_F(MockBPFMapsWrapperTest, testCreateNotYetExistingElement) {
	int key{99};
	bool value{true};
	EXPECT_TRUE(mockMapsWrapper.createElement(mockMapFD, &key, &value));
	EXPECT_EQ(mockMap.size(), 1);
	EXPECT_EQ(mockMap.at(key), value);
}

TEST_F(MockBPFMapsWrapperTest, testCreateExistingElement) {
	int key{99};
	bool value{true};
	ASSERT_TRUE(mockMapsWrapper.createElement(mockMapFD, &key, &value));
	EXPECT_FALSE(mockMapsWrapper.createElement(mockMapFD, &key, &value));
	EXPECT_EQ(mockMap.size(), 1);
	EXPECT_EQ(mockMap.at(key), value);
}

TEST_F(MockBPFMapsWrapperTest, testCreate2Elements) {
	int keyA{99}, keyB{75};
	bool valueA{true}, valueB{false};
	ASSERT_TRUE(mockMapsWrapper.createElement(mockMapFD, &keyA, &valueA));
	EXPECT_TRUE(mockMapsWrapper.createElement(mockMapFD, &keyB, &valueB));
	EXPECT_EQ(mockMap.size(), 2);
	EXPECT_EQ(mockMap.at(keyA), valueA);
	EXPECT_EQ(mockMap.at(keyB), valueB);
}

TEST_F(MockBPFMapsWrapperTest, testLookupExistingElement) {
	int key{99};
	bool value{true}, valueGot;
	ASSERT_TRUE(mockMapsWrapper.createElement(mockMapFD, &key, &value));
	EXPECT_TRUE(mockMapsWrapper.lookupElement(mockMapFD, &key, &valueGot));
	EXPECT_EQ(value, valueGot);
	EXPECT_EQ(mockMap.size(), 1);
	EXPECT_EQ(mockMap.at(key), value);
}

TEST_F(MockBPFMapsWrapperTest, testLookupNotExistingElement) {
	int key{99};
	bool valueGot;
	EXPECT_FALSE(mockMapsWrapper.lookupElement(mockMapFD, &key, &valueGot));
	EXPECT_TRUE(mockMap.empty());
}

TEST_F(MockBPFMapsWrapperTest, testUpdateExistingElement) {
	int key{99};
	bool valueA{true}, valueB{false};
	ASSERT_TRUE(mockMapsWrapper.createElement(mockMapFD, &key, &valueA));
	EXPECT_TRUE(mockMapsWrapper.updateElement(mockMapFD, &key, &valueB));
	EXPECT_EQ(mockMap.size(), 1);
	EXPECT_EQ(mockMap.at(key), valueB);
}

TEST_F(MockBPFMapsWrapperTest, testUpdateNotExistingElement) {
	int key{99};
	bool value{false};
	EXPECT_TRUE(mockMapsWrapper.updateElement(mockMapFD, &key, &value));
	EXPECT_EQ(mockMap.size(), 1);
	EXPECT_EQ(mockMap.at(key), value);
}

TEST_F(MockBPFMapsWrapperTest, testUpdateNotExistingElementDontCreate) {
	int key{99};
	bool value{false};
	EXPECT_FALSE(mockMapsWrapper.updateElement(mockMapFD, &key, &value, false));
	EXPECT_TRUE(mockMap.empty());
}

TEST_F(MockBPFMapsWrapperTest, testRemoveExistingElement) {
	int keyA{99}, keyB{75};
	bool valueA{true}, valueB{false};
	ASSERT_TRUE(mockMapsWrapper.createElement(mockMapFD, &keyA, &valueA));
	ASSERT_TRUE(mockMapsWrapper.createElement(mockMapFD, &keyB, &valueB));
	EXPECT_TRUE(mockMapsWrapper.removeElement(mockMapFD, &keyA));
	EXPECT_EQ(mockMap.size(), 1);
	EXPECT_EQ(mockMap.at(keyB), valueB);
}

TEST_F(MockBPFMapsWrapperTest, testRemoveNotExistingElement) {
	int key{99};
	EXPECT_FALSE(mockMapsWrapper.removeElement(mockMapFD, &key));
	EXPECT_TRUE(mockMap.empty());
}

TEST_F(MockBPFMapsWrapperTest, testGetNextKeyMapEmpty) {
	int prevKey{}, currKey{};
	EXPECT_FALSE(mockMapsWrapper.getNextKey(mockMapFD, nullptr, &currKey));
	EXPECT_FALSE(mockMapsWrapper.getNextKey(mockMapFD, &prevKey, &currKey));
	EXPECT_TRUE(mockMap.empty());
}

TEST_F(MockBPFMapsWrapperTest, testGetNextKeyNoSuchPrevKey) {
	int key{99};
	bool value{false};
	int prevKey{53}, currKey{};
	ASSERT_TRUE(mockMapsWrapper.createElement(mockMapFD, &key, &value));
	EXPECT_TRUE(mockMapsWrapper.getNextKey(mockMapFD, &prevKey, &currKey));
	EXPECT_EQ(currKey, key);
	EXPECT_EQ(mockMap.size(), 1);
	EXPECT_EQ(mockMap.at(key), value);
}

TEST_F(MockBPFMapsWrapperTest, testGetNextKeyInvalidPrevKey) {
	int key{99};
	bool value{false};
	int currKey{};
	ASSERT_TRUE(mockMapsWrapper.createElement(mockMapFD, &key, &value));
	EXPECT_TRUE(mockMapsWrapper.getNextKey(mockMapFD, nullptr, &currKey));
	EXPECT_EQ(currKey, key);
	EXPECT_EQ(mockMap.size(), 1);
	EXPECT_EQ(mockMap.at(key), value);
}

TEST_F(MockBPFMapsWrapperTest, testGetNextKeyLastKey) {
	int key{99};
	bool value{false};
	int currKey{};
	ASSERT_TRUE(mockMapsWrapper.createElement(mockMapFD, &key, &value));
	EXPECT_FALSE(mockMapsWrapper.getNextKey(mockMapFD, &key, &currKey));
	EXPECT_EQ(mockMap.size(), 1);
	EXPECT_EQ(mockMap.at(key), value);
}

TEST_F(MockBPFMapsWrapperTest, testGetNextKeyOk) {
	int keyA{99}, keyB{75};
	bool valueA{true}, valueB{false};
	int currKey{};
	ASSERT_TRUE(mockMapsWrapper.createElement(mockMapFD, &keyA, &valueA));
	ASSERT_TRUE(mockMapsWrapper.createElement(mockMapFD, &keyB, &valueB));
	EXPECT_TRUE(mockMapsWrapper.getNextKey(mockMapFD, nullptr, &currKey));
	EXPECT_TRUE(currKey == keyA || currKey == keyB);
	EXPECT_EQ(mockMap.size(), 2);
	EXPECT_EQ(mockMap.at(keyA), valueA);
	EXPECT_EQ(mockMap.at(keyB), valueB);
}
