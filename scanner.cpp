// scanner.cpp
// Módulo C++ exposto ao Python via pybind11.
// Faz a parte pesada: listar regiões de memória, varrer valores,
// refinar (next scan) e ler/escrever endereços específicos.
//
// Compilar:
//   c++ -O3 -Wall -shared -std=c++17 -fPIC \
//       $(python3 -m pybind11 --includes) \
//       scanner.cpp -o scanner$(python3-config --extension-suffix)

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace py = pybind11;

enum class ScanType { EXACT, CHANGED, UNCHANGED, INCREASED, DECREASED };

struct MemRegion {
    uintptr_t start;
    uintptr_t end;
    bool readable;
    bool writable;
};

class MemoryScanner {
public:
    explicit MemoryScanner(int pid) : m_pid(pid) {}

    // --- utilitário: lista regiões válidas de /proc/pid/maps ---
    std::vector<MemRegion> regions() {
        std::vector<MemRegion> out;
        std::ifstream maps("/proc/" + std::to_string(m_pid) + "/maps");
        if (!maps.is_open()) return out;

        std::string line;
        while (std::getline(maps, line)) {
            // ignora regiões especiais (vdso, vsyscall, vvar)
            if (line.find("[v") != std::string::npos) continue;

            uintptr_t start = 0, end = 0;
            char r = '-', w = '-', x = '-', p = '-';
            if (sscanf(line.c_str(), "%lx-%lx %c%c%c%c",
                       &start, &end, &r, &w, &x, &p) < 6) {
                continue;
            }
            out.push_back({start, end, r == 'r', w == 'w'});
        }
        return out;
    }

    // --- primeiro scan: varre tudo procurando um valor int32 ---
    std::vector<uintptr_t> first_scan(int32_t value) {
        std::vector<uintptr_t> matches;
        std::string mem_path = "/proc/" + std::to_string(m_pid) + "/mem";
        int fd = open(mem_path.c_str(), O_RDONLY);
        if (fd < 0) return matches;

        for (const auto& region : regions()) {
            if (!region.readable) continue;

            size_t size = region.end - region.start;
            // pula regiões absurdamente grandes (ex: mapeamentos de arquivo enormes)
            if (size > 200'000'000) continue;

            std::vector<char> buf(size);
            ssize_t n = pread(fd, buf.data(), size, region.start);
            if (n <= 0) continue;

            for (ssize_t i = 0; i + (ssize_t)sizeof(int32_t) <= n; ++i) {
                int32_t v;
                std::memcpy(&v, buf.data() + i, sizeof(v));
                if (v == value) {
                    matches.push_back(region.start + i);
                }
            }
        }
        close(fd);
        m_candidates = matches;
        m_last_values.assign(matches.size(), value);
        return matches;
    }

    // --- next scan: relê só os candidatos e filtra pela condição ---
    // scan_type: "exact" | "changed" | "unchanged" | "increased" | "decreased"
    std::vector<uintptr_t> next_scan(const std::string& scan_type,
                                      py::object value_obj = py::none()) {
        std::string mem_path = "/proc/" + std::to_string(m_pid) + "/mem";
        int fd = open(mem_path.c_str(), O_RDONLY);
        if (fd < 0) return {};

        ScanType type;
        if (scan_type == "exact") type = ScanType::EXACT;
        else if (scan_type == "changed") type = ScanType::CHANGED;
        else if (scan_type == "unchanged") type = ScanType::UNCHANGED;
        else if (scan_type == "increased") type = ScanType::INCREASED;
        else if (scan_type == "decreased") type = ScanType::DECREASED;
        else { close(fd); throw std::invalid_argument("scan_type inválido"); }

        bool has_value = !value_obj.is_none();
        int32_t target = has_value ? value_obj.cast<int32_t>() : 0;

        std::vector<uintptr_t> new_candidates;
        std::vector<int32_t> new_values;

        for (size_t i = 0; i < m_candidates.size(); ++i) {
            int32_t current = 0;
            ssize_t n = pread(fd, &current, sizeof(current), m_candidates[i]);
            if (n != sizeof(current)) continue;

            int32_t previous = m_last_values[i];
            bool keep = false;

            switch (type) {
                case ScanType::EXACT:      keep = has_value && current == target; break;
                case ScanType::CHANGED:    keep = current != previous; break;
                case ScanType::UNCHANGED:  keep = current == previous; break;
                case ScanType::INCREASED:  keep = current > previous; break;
                case ScanType::DECREASED:  keep = current < previous; break;
            }

            if (keep) {
                new_candidates.push_back(m_candidates[i]);
                new_values.push_back(current);
            }
        }
        close(fd);

        m_candidates = new_candidates;
        m_last_values = new_values;
        return m_candidates;
    }

    // --- lê o valor atual de um endereço específico ---
    int32_t read_int(uintptr_t addr) {
        std::string mem_path = "/proc/" + std::to_string(m_pid) + "/mem";
        int fd = open(mem_path.c_str(), O_RDONLY);
        if (fd < 0) throw std::runtime_error("não foi possível abrir /proc/pid/mem");

        int32_t value = 0;
        ssize_t n = pread(fd, &value, sizeof(value), addr);
        close(fd);
        if (n != sizeof(value)) throw std::runtime_error("falha ao ler endereço");
        return value;
    }

    // --- escreve um valor em um endereço específico ---
    void write_int(uintptr_t addr, int32_t value) {
        std::string mem_path = "/proc/" + std::to_string(m_pid) + "/mem";
        int fd = open(mem_path.c_str(), O_WRONLY);
        if (fd < 0) throw std::runtime_error("não foi possível abrir /proc/pid/mem para escrita (precisa de permissão)");

        ssize_t n = pwrite(fd, &value, sizeof(value), addr);
        close(fd);
        if (n != sizeof(value)) throw std::runtime_error("falha ao escrever no endereço");
    }

    // devolve os valores atuais de todos os candidatos (pra atualizar a Treeview)
    std::vector<std::pair<uintptr_t, int32_t>> current_results() {
        std::string mem_path = "/proc/" + std::to_string(m_pid) + "/mem";
        int fd = open(mem_path.c_str(), O_RDONLY);
        std::vector<std::pair<uintptr_t, int32_t>> out;
        if (fd < 0) return out;

        for (auto addr : m_candidates) {
            int32_t v = 0;
            if (pread(fd, &v, sizeof(v), addr) == sizeof(v)) {
                out.push_back({addr, v});
            }
        }
        close(fd);
        return out;
    }

    size_t candidate_count() const { return m_candidates.size(); }

private:
    int m_pid;
    std::vector<uintptr_t> m_candidates;
    std::vector<int32_t> m_last_values;
};

PYBIND11_MODULE(scanner, m) {
    m.doc() = "LibraryLin - núcleo de scan de memória em C++";

    py::class_<MemoryScanner>(m, "MemoryScanner")
        .def(py::init<int>(), py::arg("pid"))
        .def("first_scan", &MemoryScanner::first_scan, py::arg("value"))
        .def("next_scan", &MemoryScanner::next_scan,
             py::arg("scan_type"), py::arg("value") = py::none())
        .def("read_int", &MemoryScanner::read_int, py::arg("addr"))
        .def("write_int", &MemoryScanner::write_int, py::arg("addr"), py::arg("value"))
        .def("current_results", &MemoryScanner::current_results)
        .def("candidate_count", &MemoryScanner::candidate_count);
}