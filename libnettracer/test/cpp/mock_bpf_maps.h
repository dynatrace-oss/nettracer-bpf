#pragma once

#include "bpf_generic/bpf_wrapper.h"
#include <gmock/gmock.h>
#include <memory>
#include <unordered_map>

class AbstractMapWrapper {
public:
	virtual ~AbstractMapWrapper() = default;

	virtual bool createElement(const void* key, const void* value) = 0;
	virtual bool lookupElement(const void* key, void* value) const = 0;
	virtual bool updateElement(const void* key, const void* value, bool createIfDoesntExist) = 0;
	virtual bool removeElement(const void* key) = 0;
	virtual bool getNextKey(const void* previousKey, void* currentKey) const = 0;

	virtual void clear() = 0;
};

// MapWrapper does basically what BPF calls would do but on fully userspace in-memory mock maps
// For expected behavior, refer to the wrapper code in bpf_generic and BPF documentation (https://www.man7.org/linux/man-pages/man2/bpf.2.html)

template<typename Key, typename Value>
class MapWrapper final : public AbstractMapWrapper {
public:
	bool createElement(const void* key, const void* value) override {
		return map.insert(std::make_pair(*static_cast<const Key*>(key), *static_cast<const Value*>(value))).second;
	}

	bool lookupElement(const void* key, void* value) const override {
		auto it{map.find(*static_cast<const Key*>(key))};
		if (it != map.end()) {
			*static_cast<Value*>(value) = it->second;
			return true;
		}
		return false;
	}

	bool updateElement(const void* key, const void* value, bool createIfDoesntExist) override {
		if (createIfDoesntExist) {
			map.insert_or_assign(*static_cast<const Key*>(key), *static_cast<const Value*>(value));
			return true;
		}
		auto it{map.find(*static_cast<const Key*>(key))};
		if (it == map.end()) {
			return false;
		}
		it->second = *static_cast<const Value*>(value);
		return true;
	}

	bool removeElement(const void* key) override {
		return static_cast<bool>(map.erase(*static_cast<const Key*>(key)));
	}

	bool getNextKey(const void* previousKey, void* currentKey) const override {
		if (map.empty()) {
			return false;
		}

		if (previousKey == 0) {
			*static_cast<Key*>(currentKey) = map.begin()->first;
			return true;
		}

		auto it{map.find(*static_cast<const Key*>(previousKey))};
		if (it == map.end()) {
			*static_cast<Key*>(currentKey) = map.begin()->first;
			return true;
		}

		if (++it == map.end()) {
			return false;
		}

		*static_cast<Key*>(currentKey) = it->first;
		return true;
	}

	void clear() override {
		map.clear();
	}

	std::unordered_map<Key, Value> map;
};

class MockBPFMapsWrapper final : public bpf::BPFMapsWrapper {
public:
	// createNode needs manually specified mock return values
	MOCK_METHOD(int, createNode, (bpf_map_type mapType, const std::string& name, uint32_t keySize, uint32_t valueSize, uint32_t maxEntries, uint32_t mapFlags, uint32_t node), (override));

	bool createElement(int fd, const void* key, const void* value) override {
		return mapWrappers.at(fd)->createElement(key, value);
	}
	bool lookupElement(int fd, const void* key, void* value) const override {
		return mapWrappers.at(fd)->lookupElement(key, value);
	}
	bool updateElement(int fd, const void* key, const void* value, bool createIfDoesntExist = true) override {
		return mapWrappers.at(fd)->updateElement(key, value, createIfDoesntExist);
	}
	bool removeElement(int fd, const void* key) override {
		return mapWrappers.at(fd)->removeElement(key);
	}
	bool getNextKey(int fd, const void* previousKey, void* currentKey) const override {
		return mapWrappers.at(fd)->getNextKey(previousKey, currentKey);
	}

	template<typename Key, typename Value>
	std::unordered_map<Key, Value>& createMap(int fd) {
		std::unique_ptr<AbstractMapWrapper> mapWrapper{std::make_unique<MapWrapper<Key, Value>>()};
		auto it{mapWrappers.insert(std::make_pair(fd, std::move(mapWrapper))).first};
		return static_cast<MapWrapper<Key, Value>*>(it->second.get())->map;
	}

	void clearMaps() {
		mapWrappers.clear();
	}

	void clearMapsContents() {
		for (auto& wrapper : mapWrappers) {
			wrapper.second->clear();
		}
	}

private:
	using MapWrappersForFDs = std::unordered_map<int, std::unique_ptr<AbstractMapWrapper>>;

	MapWrappersForFDs mapWrappers;
};
