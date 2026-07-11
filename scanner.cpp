// scanner.cpp — v2
// Agora com candidatos "tipados" (int16/32/64, float, double), usados tanto
// pelo scan normal quanto pelo Modo IA (que testa vários tipos de uma vez).
//
// Compilar:
//   c++ -O3 -Wall -shared -std=c++17 -fPIC \
//       $(python3 -m pybind11 --includes) \
//       scanner.cpp -o scanner$(python3-config --extension-suffix)

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <unordered_map>
#include <unistd.h>
#include <vector>

namespace py = pybind11;

enum class Type { INT16, INT32, INT64, FLOAT, DOUBLE };

static std::string type_to_string(Type t) {
    switch (t) {
        case Type::INT16:  return "int16";
        case Type::INT32:  return "int32";
        case Type::INT64:  return "int64";
        case Type::FLOAT:  return "float";
        case Type::DOUBLE: return "double";
    }
    return "int32";
}

static Type type_from_string(const std::string& s) {
    if (s == "int16") return Type::INT16;
    if (s == "int32") return Type::INT32;
    if (s == "int64") return Type::INT64;
    if (s == "float") return Type::FLOAT;
    if (s == "double") return Type::DOUBLE;
    throw std::invalid_argument("tipo desconhecido: " + s);
}

static size_t type_size(Type t) {
    switch (t) {
        case Type::INT16:  return 2;
        case Type::INT32:  return 4;
        case Type::INT64:  return 8;
        case Type::FLOAT:  return 4;
        case Type::DOUBLE: return 8;
    }
    return 4;
}

// converte um double genérico pros bytes exatos do tipo, pra usar como padrão de busca
static std::vector<char> value_to_bytes(Type t, double value) {
    std::vector<char> bytes(type_size(t));
    switch (t) {
        case Type::INT16: { int16_t v = (int16_t)value; std::memcpy(bytes.data(), &v, sizeof(v)); break; }
        case Type::INT32: { int32_t v = (int32_t)value; std::memcpy(bytes.data(), &v, sizeof(v)); break; }
        case Type::INT64: { int64_t v = (int64_t)value; std::memcpy(bytes.data(), &v, sizeof(v)); break; }
        case Type::FLOAT: { float v = (float)value; std::memcpy(bytes.data(), &v, sizeof(v)); break; }
        case Type::DOUBLE:{ double v = value; std::memcpy(bytes.data(), &v, sizeof(v)); break; }
    }
    return bytes;
}

// lê bytes crus e devolve como double (pra poder comparar genericamente)
static double bytes_to_value(Type t, const char* data) {
    switch (t) {
        case Type::INT16: { int16_t v; std::memcpy(&v, data, sizeof(v)); return (double)v; }
        case Type::INT32: { int32_t v; std::memcpy(&v, data, sizeof(v)); return (double)v; }
        case Type::INT64: { int64_t v; std::memcpy(&v, data, sizeof(v)); return (double)v; }
        case Type::FLOAT: { float v;  std::memcpy(&v, data, sizeof(v)); return (double)v; }
        case Type::DOUBLE:{ double v; std::memcpy(&v, data, sizeof(v)); return v; }
    }
    return 0.0;
}

struct MemRegion {
    uintptr_t start;
    uintptr_t end;
    bool readable;
};

struct Candidate {
    uintptr_t addr;
    Type type;
    double last_value;
};

class MemoryScanner {
public:
    explicit MemoryScanner(int pid) : m_pid(pid) {}

    std::vector<MemRegion> regions() {
        std::vector<MemRegion> out;
        std::ifstream maps("/proc/" + std::to_string(m_pid) + "/maps");
        if (!maps.is_open()) return out;

        std::string line;
        while (std::getline(maps, line)) {
            if (line.find("[v") != std::string::npos) continue;
            uintptr_t start = 0, end = 0;
            char r = '-', w = '-', x = '-', p = '-';
            if (sscanf(line.c_str(), "%lx-%lx %c%c%c%c", &start, &end, &r, &w, &x, &p) < 6) continue;
            out.push_back({start, end, r == 'r'});
        }
        return out;
    }

    // --- scan clássico: um único tipo escolhido pelo usuário ---
    py::list first_scan(const std::string& type_str, double value) {
        Type type = type_from_string(type_str);
        m_candidates.clear();

        std::string mem_path = "/proc/" + std::to_string(m_pid) + "/mem";
        int fd = open(mem_path.c_str(), O_RDONLY);
        if (fd < 0) return py::list();

        auto pattern = value_to_bytes(type, value);
        size_t tsize = pattern.size();

        for (const auto& region : regions()) {
            if (!region.readable) continue;

            size_t size = region.end - region.start;
            if (size > 200'000'000) continue;

            std::vector<char> buf(size);
            ssize_t n = pread(fd, buf.data(), size, region.start);
            if (n <= 0) continue;

            for (ssize_t i = 0; i + (ssize_t)tsize <= n; ++i) {
                if (std::memcmp(buf.data() + i, pattern.data(), tsize) == 0) {
                    m_candidates.push_back({region.start + (uintptr_t)i, type, value});
                }
            }
        }
        close(fd);
        return candidates_as_pylist();
    }

    // --- Modo IA: testa vários tipos numéricos ao mesmo tempo, sem o usuário escolher ---
    py::list ai_scan(double value) {
        m_candidates.clear();

        std::string mem_path = "/proc/" + std::to_string(m_pid) + "/mem";
        int fd = open(mem_path.c_str(), O_RDONLY);
        if (fd < 0) return py::list();

        std::vector<Type> types = {Type::INT16, Type::INT32, Type::INT64, Type::FLOAT, Type::DOUBLE};
        bool is_integral = (value == std::floor(value));

        for (const auto& region : regions()) {
            if (!region.readable) continue;

            size_t size = region.end - region.start;
            if (size > 200'000'000) continue;

            std::vector<char> buf(size);
            ssize_t n = pread(fd, buf.data(), size, region.start);
            if (n <= 0) continue;

            // lê a região uma vez só e testa todos os tipos no mesmo buffer
            for (Type type : types) {
                if (!is_integral && (type == Type::INT16 || type == Type::INT32 || type == Type::INT64)) {
                    continue; // valor não-inteiro não faz sentido testar como int
                }
                auto pattern = value_to_bytes(type, value);
                size_t tsize = pattern.size();

                for (ssize_t i = 0; i + (ssize_t)tsize <= n; ++i) {
                    if (std::memcmp(buf.data() + i, pattern.data(), tsize) == 0) {
                        m_candidates.push_back({region.start + (uintptr_t)i, type, value});
                    }
                }
            }
        }
        close(fd);
        deduplicate_by_address();
        return candidates_as_pylist();
    }

    // --- next scan: relê os candidatos (de qualquer tipo) e filtra pela condição ---
    py::list next_scan(const std::string& scan_type, py::object value_obj = py::none()) {
        std::string mem_path = "/proc/" + std::to_string(m_pid) + "/mem";
        int fd = open(mem_path.c_str(), O_RDONLY);
        if (fd < 0) return py::list();

        bool has_value = !value_obj.is_none();
        double target = has_value ? value_obj.cast<double>() : 0.0;

        std::vector<Candidate> kept;
        for (auto& c : m_candidates) {
            size_t tsize = type_size(c.type);
            std::vector<char> buf(tsize);
            ssize_t n = pread(fd, buf.data(), tsize, c.addr);
            if (n != (ssize_t)tsize) continue;

            double current = bytes_to_value(c.type, buf.data());
            bool keep = false;

            if (scan_type == "exact")            keep = has_value && current == target;
            else if (scan_type == "changed")     keep = current != c.last_value;
            else if (scan_type == "unchanged")   keep = current == c.last_value;
            else if (scan_type == "increased")   keep = current > c.last_value;
            else if (scan_type == "decreased")   keep = current < c.last_value;
            else throw std::invalid_argument("scan_type inválido");

            if (keep) kept.push_back({c.addr, c.type, current});
        }
        close(fd);

        m_candidates = kept;
        return candidates_as_pylist();
    }

    double read_value(uintptr_t addr, const std::string& type_str) {
        Type type = type_from_string(type_str);
        std::string mem_path = "/proc/" + std::to_string(m_pid) + "/mem";
        int fd = open(mem_path.c_str(), O_RDONLY);
        if (fd < 0) throw std::runtime_error("não foi possível abrir /proc/pid/mem");

        std::vector<char> buf(type_size(type));
        ssize_t n = pread(fd, buf.data(), buf.size(), addr);
        close(fd);
        if (n != (ssize_t)buf.size()) throw std::runtime_error("falha ao ler endereço");
        return bytes_to_value(type, buf.data());
    }

    void write_value(uintptr_t addr, const std::string& type_str, double value) {
        Type type = type_from_string(type_str);
        std::string mem_path = "/proc/" + std::to_string(m_pid) + "/mem";
        int fd = open(mem_path.c_str(), O_WRONLY);
        if (fd < 0) throw std::runtime_error("não foi possível abrir /proc/pid/mem para escrita");

        auto bytes = value_to_bytes(type, value);
        ssize_t n = pwrite(fd, bytes.data(), bytes.size(), addr);
        close(fd);
        if (n != (ssize_t)bytes.size()) throw std::runtime_error("falha ao escrever no endereço");
    }

    py::list current_results() {
        std::string mem_path = "/proc/" + std::to_string(m_pid) + "/mem";
        int fd = open(mem_path.c_str(), O_RDONLY);
        py::list out;
        if (fd < 0) return out;

        for (auto& c : m_candidates) {
            size_t tsize = type_size(c.type);
            std::vector<char> buf(tsize);
            if (pread(fd, buf.data(), tsize, c.addr) == (ssize_t)tsize) {
                double v = bytes_to_value(c.type, buf.data());
                c.last_value = v;
                out.append(py::make_tuple(
                    "0x" + to_hex(c.addr), type_to_string(c.type), v));
            }
        }
        close(fd);
        return out;
    }

    size_t candidate_count() const { return m_candidates.size(); }

private:
    int m_pid;
    std::vector<Candidate> m_candidates;

    static std::string to_hex(uintptr_t v) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%lx", v);
        return std::string(buf);
    }

    // quando o Modo IA acha o mesmo endereço batendo com vários tipos
    // (comum quando os bytes vizinhos são zero por padding/alinhamento),
    // mantém só o tipo mais específico — o de menor tamanho em bytes.
    void deduplicate_by_address() {
        std::unordered_map<uintptr_t, Candidate> best;
        for (const auto& c : m_candidates) {
            auto it = best.find(c.addr);
            if (it == best.end() || type_size(c.type) < type_size(it->second.type)) {
                best[c.addr] = c;
            }
        }

        m_candidates.clear();
        m_candidates.reserve(best.size());
        for (auto& [addr, c] : best) {
            m_candidates.push_back(c);
        }
        std::sort(m_candidates.begin(), m_candidates.end(),
                  [](const Candidate& a, const Candidate& b) { return a.addr < b.addr; });
    }

    py::list candidates_as_pylist() {
        py::list out;
        for (auto& c : m_candidates) {
            out.append(py::make_tuple(
                "0x" + to_hex(c.addr), type_to_string(c.type), c.last_value));
        }
        return out;
    }
};

PYBIND11_MODULE(scanner, m) {
    m.doc() = "LibraryLin - núcleo de scan de memória em C++ (multi-tipo + Modo IA)";

    py::class_<MemoryScanner>(m, "MemoryScanner")
        .def(py::init<int>(), py::arg("pid"))
        .def("first_scan", &MemoryScanner::first_scan, py::arg("type"), py::arg("value"))
        .def("ai_scan", &MemoryScanner::ai_scan, py::arg("value"))
        .def("next_scan", &MemoryScanner::next_scan,
             py::arg("scan_type"), py::arg("value") = py::none())
        .def("read_value", &MemoryScanner::read_value, py::arg("addr"), py::arg("type"))
        .def("write_value", &MemoryScanner::write_value,
             py::arg("addr"), py::arg("type"), py::arg("value"))
        .def("current_results", &MemoryScanner::current_results)
        .def("candidate_count", &MemoryScanner::candidate_count);
}
