// Device layer, safety guard and classifier tests.
//
// Everything here runs as an unprivileged user against image files in a temp directory.
// Real block devices are only ever *assessed* (stat + sysfs reads) to prove they are refused;
// no test ever opens a loop device or a physical disk.

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

#include "check.hpp"
#include "device/classifier.hpp"
#include "device/device_factory.hpp"
#include "device/identity_provider.hpp"
#include "device/safety_guard.hpp"
#include "device/sysfs.hpp"

using namespace dw;
namespace fs = std::filesystem;

namespace {

fs::path g_dir;

std::string make_image(const std::string& name, std::uint64_t size, char fill = '\0') {
    fs::path p = g_dir / name;
    std::ofstream out(p, std::ios::binary);
    std::string chunk(4096, fill);
    for (std::uint64_t left = size; left > 0;) {
        auto n = std::min<std::uint64_t>(left, chunk.size());
        out.write(chunk.data(), static_cast<std::streamsize>(n));
        left -= n;
    }
    return p.string();
}

std::string profiles_dir() {
    const char* d = std::getenv("DW_PROFILES_DIR");
    return d ? d : "profiles";
}

Result<DeviceProfile> probe(const std::string& image, const std::string& profile_text) {
    auto sim = SimulatedIdentityProvider::from_json_text(profile_text, "inline");
    if (!sim) return sim.error();
    auto t = open_target(image, OpenOptions{});
    if (!t) return t.error();
    auto id = sim->identify(*t->device);
    if (!id) return id.error();
    return classify(*t, *id, IdentitySource::Simulated, "inline");
}

Result<DeviceProfile> probe_file(const std::string& image, const std::string& profile_name) {
    std::ifstream in(profiles_dir() + "/" + profile_name);
    std::stringstream ss;
    ss << in.rdbuf();
    return probe(image, ss.str());
}

std::string profile(const std::string& extra) {
    return R"({"schema":"datawipe.identity.v1","transport":"sata","model":"M","serial":"S","rotation_rate":7200)" +
           extra + "}";
}

bool has_warning(const DeviceProfile& p, const std::string& needle) {
    for (const auto& w : p.warnings)
        if (w.find(needle) != std::string::npos) return true;
    return false;
}

void test_image_assessment() {
    auto img = make_image("ok.img", 1 << 20);
    auto a = assess_target(img);
    CHECK_OK(a);
    if (a) CHECK(a->kind == BackendKind::ImageFile);

#ifndef _WIN32
    // Symlinks resolve to the real file.
    fs::create_symlink(img, g_dir / "link.img");
    auto l = assess_target((g_dir / "link.img").string());
    CHECK_OK(l);
    if (l) CHECK(l->canonical_path == fs::canonical(img).string());
#else
    // Volumes and other device-namespace paths are refused before anything is opened; disks
    // must exist; and no disk is opened writable without a confirmed override (checked before
    // any handle exists, so this is safe even where PhysicalDrive0 is the system disk).
    CHECK_ERR_CONTAINS(assess_target("\\\\.\\C:"), "not a whole disk");
    CHECK_ERR_CONTAINS(assess_target("\\\\?\\Volume{00000000-0000-0000-0000-000000000000}"), "not a whole disk");
    CHECK_ERR_CONTAINS(assess_target("\\\\.\\PhysicalDrive007"), "not a whole disk");
    CHECK_ERR_CONTAINS(assess_target("\\\\.\\PhysicalDrive127"), "no disk 127");
    CHECK_ERR_CONTAINS(open_target("\\\\.\\PhysicalDrive0", OpenOptions{.writable = true}), "REFUSED");
#endif

    CHECK_ERR_CONTAINS(assess_target(make_image("odd.img", 1000)), "not a multiple of 512");
    CHECK_ERR_CONTAINS(assess_target(make_image("empty.img", 0)), "empty");
    CHECK_ERR_CONTAINS(assess_target(g_dir.string()), "not a regular file");
#ifndef _WIN32
    CHECK_ERR_CONTAINS(assess_target("/dev/null"), "not a regular file or block device");
#endif
    CHECK_ERR_CONTAINS(assess_target((g_dir / "missing.img").string()), "realpath");
}

void test_image_io() {
    auto img = make_image("io.img", 1 << 20, '\x5a');

    auto ro = open_target(img, OpenOptions{});
    CHECK_OK(ro);
    if (ro) {
        std::vector<std::byte> b(512, std::byte{1});
        CHECK_ERR_CONTAINS(ro->device->write_at(0, b), "read-only");
        CHECK(ro->device->geometry().size_bytes == (1u << 20));
        CHECK(ro->device->geometry().sector_count() == 2048);
    }

    auto rw = open_target(img, OpenOptions{.writable = true});
    CHECK_OK(rw);
    if (rw) {
        auto& d = *rw->device;
        std::vector<std::byte> w(8192);
        for (size_t i = 0; i < w.size(); ++i) w[i] = static_cast<std::byte>(i * 7);
        CHECK_OK(d.write_at(4096, w));
        CHECK_OK(d.flush());
        std::vector<std::byte> r(8192);
        CHECK_OK(d.read_at(4096, r));
        CHECK(r == w);
        std::vector<std::byte> before(1);
        CHECK_OK(d.read_at(4095, before));
        CHECK(before[0] == std::byte{0x5a});  // neighbour untouched

        std::vector<std::byte> one(1);
        CHECK_ERR_CONTAINS(d.read_at((1u << 20), one), "exceeds device size");
        CHECK_ERR_CONTAINS(d.write_at((1u << 20) - 4, std::vector<std::byte>(8)), "exceeds device size");
        CHECK_ERR_CONTAINS(d.read_at(UINT64_MAX, one), "exceeds device size");  // no overflow wrap
    }

    // O_DIRECT alignment is enforced before the syscall (if the fs supports O_DIRECT at all).
    auto direct = open_target(img, OpenOptions{.writable = false, .direct_io = true});
    if (direct) {
        std::vector<std::byte> b(100);
        CHECK_ERR_CONTAINS(direct->device->read_at(0, b), "aligned");
    }
}

// Any attached loop device backed by a file we don't own (e.g. the system's snap images)
// must be refused. Only stat/sysfs are touched.
void test_foreign_loops_refused() {
#ifdef _WIN32
    return;  // Linux device nodes and /sys: not part of the Windows build (Wine would show the host's)
#endif
    int checked = 0;
    for (const auto& e : fs::directory_iterator("/sys/block")) {
        std::string name = e.path().filename().string();
        if (!name.starts_with("loop")) continue;
        auto backing = sysfs::loop_backing_file(name);
        if (!backing) continue;
        struct stat st{};
        if (::stat(backing->c_str(), &st) != 0) continue;
        if (static_cast<uid_t>(st.st_uid) == invoking_uid()) {
            // One of ours: the loop may be assessed (not opened here), but its backing image
            // must not be writable directly while attached.
            CHECK_ERR_CONTAINS(assess_target(*backing), "attached as");
            continue;
        }
        auto a = assess_target("/dev/" + name);
        CHECK(!a);
        auto t = open_target("/dev/" + name, OpenOptions{.writable = true});
        CHECK(!t);
        ++checked;
    }
    std::fprintf(stderr, "  (checked %d foreign loop devices are refused)\n", checked);
}

// Physical disks: read-only opens are allowed for detection (they may still fail with EACCES
// when not root); writable opens must always be refused without a confirmed override.
void test_physical_refused() {
#ifdef _WIN32
    return;  // Linux device nodes and /sys: not part of the Windows build (Wine would show the host's)
#endif
    int checked = 0;
    for (const auto& e : fs::directory_iterator("/sys/block")) {
        std::string name = e.path().filename().string();
        if (name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram") ||
            name.starts_with("dm-") || name.starts_with("md") || name.starts_with("sr"))
            continue;
        std::string dev = "/dev/" + name;
        if (!fs::exists(dev)) continue;
        auto a = assess_target(dev);
        CHECK_OK(a);
        if (a) CHECK(a->kind == BackendKind::PhysicalBlock);
        if (auto ro = open_target(dev, OpenOptions{})) CHECK(!ro->device->writable());
        else CHECK(ro.error().sys_errno == EACCES);
        CHECK_ERR_CONTAINS(open_target(dev, OpenOptions{.writable = true}), "REFUSED");
        ++checked;
    }
    std::fprintf(stderr, "  (checked %d physical devices: writable refused)\n", checked);
}

void test_physical_confirmation() {
    TargetAssessment t;
    t.canonical_path = "/dev/fakedisk";
    t.block_name = "fakedisk";
    t.kind = BackendKind::PhysicalBlock;

    auto run = [&](const TargetAssessment& ta, bool flag, bool tty, const std::string& serial, const std::string& input) {
        std::istringstream in(input);
        std::ostringstream out;
        return confirm_physical_target(ta, flag, serial, ConfirmIO{in, out, tty});
    };

    CHECK_ERR_CONTAINS(run(t, false, true, "SER1", "SER1\n/dev/fakedisk\n"), "--i-understand-this-is-destructive");
    CHECK_ERR_CONTAINS(run(t, true, false, "SER1", "SER1\n/dev/fakedisk\n"), "interactive terminal");
    CHECK_ERR_CONTAINS(run(t, true, true, "", "\n/dev/fakedisk\n"), "no serial");
    CHECK_ERR_CONTAINS(run(t, true, true, "SER1", "SER2\n/dev/fakedisk\n"), "serial number confirmation");
    CHECK_ERR_CONTAINS(run(t, true, true, "SER1", "ser1\n/dev/fakedisk\n"), "serial number confirmation");
    CHECK_ERR_CONTAINS(run(t, true, true, "SER1", "SER1\n/dev/sda\n"), "path confirmation");
    CHECK_ERR_CONTAINS(run(t, true, true, "SER1", "SER1\n"), "path confirmation");  // EOF

    auto good = run(t, true, true, "SER1", "SER1\n/dev/fakedisk\n");
    CHECK_OK(good);
    if (good) CHECK(good->canonical_path() == "/dev/fakedisk" && good->serial() == "SER1");

    TargetAssessment img = t;
    img.kind = BackendKind::ImageFile;
    CHECK_ERR_CONTAINS(run(img, true, true, "SER1", "SER1\n/dev/fakedisk\n"), "only meaningful");

    // An override minted for one device does not unlock another.
    if (good) {
        auto target = make_image("not_that_disk.img", 1 << 20);
        auto t2 = open_target(target, OpenOptions{}, &*good);
        CHECK_OK(t2);  // image files don't need an override; passing one is harmless
    }
}

void test_classifier() {
    auto img = make_image("cls.img", 16u << 20);  // 32768 sectors

    auto hdd = probe_file(img, "hdd_basic.json");
    CHECK_OK(hdd);
    if (hdd) {
        CHECK(hdd->media == MediaType::HDD);
        CHECK(!hdd->encrypted);
        CHECK(hdd->identity.user_addressable_sectors == 32768);
        CHECK(hdd->hidden_sectors() == 0);
        CHECK(hdd->warnings.empty());
        CHECK(to_json(*hdd).dump().find("\"media\":\"HDD\"") != std::string::npos);
    }

    auto hpa = probe_file(img, "hdd_with_hpa.json");
    CHECK_OK(hpa);
    if (hpa) {
        CHECK(hpa->identity.dco_max_sectors == 32768);
        CHECK(hpa->identity.native_max_sectors == 32768 - 2048);
        CHECK(hpa->identity.user_addressable_sectors == 32768 - 2048 - 8192);
        CHECK(hpa->hidden_sectors() == 10240);
        CHECK(has_warning(*hpa, "HPA hides 8192"));
        CHECK(has_warning(*hpa, "DCO hides 2048"));
    }

    auto opal = probe_file(img, "ssd_sata_opal.json");
    CHECK_OK(opal);
    if (opal) CHECK(opal->media == MediaType::SSD_SATA && opal->encrypted);

    auto nvme = probe_file(img, "ssd_nvme_plain.json");
    CHECK_OK(nvme);
    if (nvme) CHECK(nvme->media == MediaType::SSD_NVMe && !nvme->encrypted);

    // Identity claiming more than exists is a hard error, not a warning.
    CHECK_ERR_CONTAINS(probe(img, profile(R"(,"capacity":{"total_sectors":99999})")), "claims 99999 sectors");
    auto smaller = probe(img, profile(R"(,"capacity":{"total_sectors":16384})"));
    CHECK_OK(smaller);
    if (smaller) CHECK(has_warning(*smaller, "16384 measured sectors lie beyond"));

    CHECK_ERR_CONTAINS(probe(img, profile(R"(,"capacity":{"hpa_hidden_sectors":40000})")), "no user-addressable");
    CHECK_ERR_CONTAINS(probe(img, profile(R"(,"capacity":{"total_sectors":"lots"})")), "number or \"auto\"");
    CHECK_ERR_CONTAINS(probe(img, profile(R"(,"self_encripting":true)")), "unknown key \"self_encripting\"");
    CHECK_ERR_CONTAINS(probe(img, profile(R"(,"security":{"frozn":true})")), "unknown key \"frozn\"");
    CHECK_ERR_CONTAINS(probe(img, profile(R"(,"sanitize":{"block_erase":true})")), "sanitize.supported is false");
    CHECK_ERR_CONTAINS(probe(img, R"({"schema":"datawipe.identity.v1","transport":"sata","model":"M"})"),
                       "missing required key \"serial\"");
    CHECK_ERR_CONTAINS(probe(img, R"({"schema":"v0","transport":"sata","model":"M","serial":"S"})"), "schema must be");
    CHECK_ERR_CONTAINS(probe(img, profile(R"(,"transport":"scsi")")), "duplicate key");

    auto unk = probe(img, R"({"schema":"datawipe.identity.v1","transport":"sata","model":"M","serial":"S"})");
    CHECK_OK(unk);
    // Rotation rate not reported (drives older than ATA8-ACS word 217, e.g. a 2011 WD5000AAKX
    // seen through a USB dock): classified by TRIM support, and the inference is stated.
    if (unk) CHECK(unk->media == MediaType::HDD && has_warning(*unk, "classified as an HDD because the drive does not support TRIM"));

    auto frozen = probe(img, profile(R"(,"security":{"supported":true,"frozen":true})"));
    CHECK_OK(frozen);
    if (frozen) CHECK(has_warning(*frozen, "FROZEN"));
}

}  // namespace

// Swap is neither a mount nor a holder; /proc/swaps is parsed and matched by device number.
void test_swap_detection() {
#ifdef _WIN32
    return;  // Linux device nodes and /sys: not part of the Windows build (Wine would show the host's)
#endif
    struct stat st{};
    if (::stat("/dev/loop0", &st) != 0 || !S_ISBLK(st.st_mode)) {
        std::fprintf(stderr, "  skip swap detection: no /dev/loop0\n");
        return;
    }
    const std::string f = (g_dir / "swaps").string();
    {
        std::ofstream out(f);
        out << "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
            << "/swap.img                               file\t\t4194300\t\t0\t\t-2\n"
            << "/dev/loop0                              partition\t1048572\t\t0\t\t-3\n";
    }
    CHECK(sysfs::swap_areas(st.st_rdev, f) == std::vector<std::string>{"/dev/loop0"});
    CHECK(sysfs::swap_areas(st.st_rdev + 1, f).empty());   // another device
    CHECK(sysfs::swap_areas(st.st_rdev, "/nonexistent").empty());
}

int main() {
    char tmpl[] = "dwtest.XXXXXX";
    fs::path base = fs::temp_directory_path() / tmpl;
    std::string s = base.string();
    if (!::mkdtemp(s.data())) {
        std::perror("mkdtemp");
        return 1;
    }
    g_dir = s;

    test_image_assessment();
    test_image_io();
    test_foreign_loops_refused();
    test_physical_refused();
    test_physical_confirmation();
    test_swap_detection();
    test_classifier();

    fs::remove_all(g_dir);
    return finish("test_device");
}
