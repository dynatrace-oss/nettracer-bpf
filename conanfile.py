from conan import ConanFile
from conan.tools.files import copy
import os

class NetTracerConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps", "CMakeToolchain"

    def requirements(self):
        self.requires("fmt/10.2.1")
        self.requires("spdlog/1.14.0")
        self.requires("boost/1.84.0")
        self.requires("gtest/1.14.0")

    def generate(self):
        for dep in self.dependencies.values():
            copy(self, "license*",
                 src=dep.package_folder,
                 dst=os.path.join(self.build_folder, "licenses", dep.ref.name),
                 ignore_case=True)