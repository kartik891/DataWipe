#include "device/sysfs.hpp"

#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <filesystem>
#include <fstream>
#include <sstream>

namespace dw::sysfs {

namespace fs = std::filesystem;

namespace {

std::string trim(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == ' ' || s.back() == '\t' || s.back() == '\0'))
        s.pop_back();
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    return s.substr(i);
}

std::vector<std::string> list_dir(const std::string& dir) {
    std::vector<std::string> out;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(dir, ec)) out.push_back(e.path().filename().string());
    return out;
}

// /proc/self/mountinfo escapes space, tab, newline and backslash as \ooo octal.
std::string unescape_mountinfo(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 3 < s.size()) {
            int v = 0;
            bool octal = true;
            for (size_t k = 1; k <= 3; ++k) {
                if (s[i + k] < '0' || s[i + k] > '7') { octal = false; break; }
                v = v * 8 + (s[i + k] - '0');
            }
            if (octal) { out += static_cast<char>(v); i += 3; continue; }
        }
        out += s[i];
    }
    return out;
}

}  // namespace

Result<std::string> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return sys_error("read " + path);
    std::ostringstream ss;
    ss << in.rdbuf();
    return trim(ss.str());
}

Result<std::string> block_name(dev_t rdev) {
    std::string link = "/sys/dev/block/" + std::to_string(major(rdev)) + ":" + std::to_string(minor(rdev));
    std::error_code ec;
    fs::path target = fs::read_symlink(link, ec);
    if (ec) return error("no sysfs entry " + link + " (" + ec.message() + ")");
    return target.filename().string();
}

std::string block_dir(const std::string& name) { return "/sys/class/block/" + name; }

bool is_partition(const std::string& name) {
    std::error_code ec;
    return fs::exists(block_dir(name) + "/partition", ec);
}

std::vector<std::string> partitions(const std::string& name) {
    std::vector<std::string> out;
    for (const auto& child : list_dir(block_dir(name) + "/")) {
        std::error_code ec;
        if (child.starts_with(name) && fs::exists(block_dir(name) + "/" + child + "/partition", ec))
            out.push_back(child);
    }
    return out;
}

std::vector<std::string> holders(const std::string& name) { return list_dir(block_dir(name) + "/holders"); }

Result<void> rescan_disk(const std::string& block_name) {
    const std::string path = "/sys/block/" + block_name + "/device/rescan";
    std::ofstream f(path);
    if (!f) return sys_error("open " + path);
    f << "1\n";
    f.flush();
    if (!f) return sys_error("write " + path);
    return ok();
}

std::vector<std::string> swap_areas(dev_t rdev, const std::string& swaps_file) {
    // /proc/swaps: header line, then "<path> <type> <size> <used> <priority>". Paths are
    // compared by device number, so /dev/disk/by-uuid/... and /dev/sda2 both match.
    std::vector<std::string> out;
    std::ifstream in(swaps_file);
    std::string line;
    std::getline(in, line);
    while (std::getline(in, line)) {
        std::istringstream ls(line);
        std::string path, type;
        if (!(ls >> path >> type) || type != "partition") continue;  // swap files live on a mounted fs
        struct stat st{};
        if (::stat(unescape_mountinfo(path).c_str(), &st) == 0 && S_ISBLK(st.st_mode) && st.st_rdev == rdev)
            out.push_back(path);
    }
    return out;
}

std::vector<std::string> mount_points(dev_t rdev) {
    // mountinfo line: <id> <parent> <major:minor> <root> <mount point> ...
    std::vector<std::string> out;
    std::ifstream in("/proc/self/mountinfo");
    const std::string want = std::to_string(major(rdev)) + ":" + std::to_string(minor(rdev));
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ls(line);
        std::string id, parent, majmin, root, mnt;
        if (!(ls >> id >> parent >> majmin >> root >> mnt)) continue;
        if (majmin == want) out.push_back(unescape_mountinfo(mnt));
    }
    return out;
}

std::optional<std::string> loop_backing_file(const std::string& loop_name) {
    auto r = read_file(block_dir(loop_name) + "/loop/backing_file");
    if (!r || r->empty()) return std::nullopt;
    return *r;
}

std::vector<std::string> loops_backed_by(dev_t file_dev, ino_t file_ino) {
    std::vector<std::string> out;
    for (const auto& name : list_dir("/sys/block")) {
        if (!name.starts_with("loop")) continue;
        auto backing = loop_backing_file(name);
        if (!backing) continue;
        struct stat st{};
        // A deleted backing file shows as "path (deleted)"; stat fails and it cannot be ours.
        if (::stat(backing->c_str(), &st) == 0 && st.st_dev == file_dev && st.st_ino == file_ino)
            out.push_back(name);
    }
    return out;
}

Result<std::string> device_serial(const std::string& name) {
    const std::string dev = block_dir(name) + "/device";
    if (auto s = read_file(dev + "/serial"); s && !s->empty()) return *s;

    // VPD page 0x80 (Unit Serial Number): 4-byte header, byte 3 = page length, then ASCII.
    {
        std::ifstream in(dev + "/vpd_pg80", std::ios::binary);
        if (in) {
            std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            if (raw.size() > 4 && static_cast<unsigned char>(raw[1]) == 0x80) {
                size_t len = static_cast<unsigned char>(raw[3]);
                std::string serial = trim(raw.substr(4, len));
                if (!serial.empty()) return serial;
            }
        }
    }

    if (auto w = read_file(dev + "/wwid"); w && !w->empty()) return *w;
    return error("kernel exposes no serial number for " + name);
}

}  // namespace dw::sysfs
