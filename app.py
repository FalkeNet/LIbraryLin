"""
app.py — LibraryLin com pywebview.

A UI é HTML/CSS puro em (ui/index.html), reaproveitando o mesmo visual do site.
O pesado continua em C++ (scanner.cpp compilado via pybind11); este arquivo
só faz a ponte entre o JS da janela e o módulo `scanner`.
"""

import webview
import scanner  # módulo compilado a partir de scanner.cpp


class Api:
    def __init__(self):
        self.mem_scanner: scanner.MemoryScanner | None = None

    def first_scan(self, pid: int, value: int):
        self.mem_scanner = scanner.MemoryScanner(pid)
        addresses = self.mem_scanner.first_scan(value)
        return [[hex(a), value] for a in addresses]

    def next_scan(self, scan_type: str, value):
        if self.mem_scanner is None:
            return []
        if scan_type == "exact":
            addresses = self.mem_scanner.next_scan(scan_type, int(value))
        else:
            addresses = self.mem_scanner.next_scan(scan_type)
        current = dict(self.mem_scanner.current_results())
        return [[hex(a), current.get(a, "?")] for a in addresses]

    def current_results(self):
        if self.mem_scanner is None:
            return []
        return [[hex(a), v] for a, v in self.mem_scanner.current_results()]

    def write_value(self, addr_hex: str, value: int):
        if self.mem_scanner is None:
            raise RuntimeError("nenhum scan ativo")
        self.mem_scanner.write_int(int(addr_hex, 16), value)
        return True


if __name__ == "__main__":
    api = Api()
    webview.create_window(
        "LibraryLin",
        "ui/index.html",
        js_api=api,
        width=760,
        height=560,
        background_color="#0b0f14",
    )
    webview.start()
