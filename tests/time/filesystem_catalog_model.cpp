#include "kernel/win/filesystem.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <string>

int main()
{
    win_filesystem fs;
    constexpr std::size_t count = 5000;
    for (std::size_t i = 0; i < count; ++i) {
        fs.create_directory("C:/Windows/System32/catroot/empty/" + std::to_string(i));
        fs.create("C:/Windows/System32/catroot/tree/" + std::to_string(i) + "/ordinary.bin");
    }
    auto scan = fs.enumerate_files_under("C:/Windows/System32/catroot", ".cat", count, 0);
    assert(!scan.limit_exceeded && scan.examined == count && scan.paths.empty());
    scan = fs.enumerate_files_under("C:/Windows/System32/catroot", ".cat", 100, 8);
    assert(scan.limit_exceeded && scan.examined == 100 && scan.paths.empty());
    fs.create("C:/Windows/System32/catroot/a.cat");
    fs.create("C:/Windows/System32/catroot/nested/B.CAT");
    fs.create("C:/Windows/System32/catrootEvil/not-a-member.cat");
    scan = fs.enumerate_files_under("\\SystemRoot\\System32\\CATROOT\\", ".CAT", count + 3, 2);
    assert(!scan.limit_exceeded && scan.examined == count + 3 && scan.paths.size() == 2);
    std::sort(scan.paths.begin(), scan.paths.end());
    assert(scan.paths[0] == "c:/windows/system32/catroot/a.cat");
    assert(scan.paths[1] == "c:/windows/system32/catroot/nested/b.cat");
    scan = fs.enumerate_files_under("C:/Windows/System32/catroot", ".cat", count + 3, 1);
    assert(scan.limit_exceeded && scan.examined <= count + 3 && scan.paths.size() == 1);
    scan = fs.enumerate_files_under("C:/Windows/System32/catroot", ".cat", 0, 2);
    assert(scan.limit_exceeded && scan.examined == 0 && scan.paths.empty());
    win_filesystem empty;
    empty.create_directory("C:/Windows/System32/catroot");
    scan = empty.enumerate_files_under("C:/Windows/System32/catroot", ".cat", 0, 0);
    assert(!scan.limit_exceeded && scan.examined == 0 && scan.paths.empty());
    std::cout << "filesystem_catalog_model: PASS (5000 files/5000 empty directories, single scan)\n";
}
