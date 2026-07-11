"""
app.py — LibraryLin (pywebview)

Recursos desta versão:
- seleção de processo (lista /proc, sem precisar digitar PID)
- edição direta de valores
- freeze (thread em background que reescreve o valor continuamente)
- Modo IA (ai_scan): testa vários tipos numéricos ao mesmo tempo
- i18n: carrega textos da UI a partir de lang/<idioma>.json,
  lendo o idioma de config.json (gerado opcionalmente pelo site de download)
"""

import json
import os
import threading
import time

import webview
import scanner  # módulo compilado a partir de scanner.cpp

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
LANG_DIR = os.path.join(APP_DIR, "lang")
FREEZE_INTERVAL = 0.1  # segundos entre reescritas do freeze


def load_language() -> str:
    """Lê o idioma salvo em config.json. Se não existir, usa pt-br."""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("language", "pt-br")
    except (FileNotFoundError, json.JSONDecodeError):
        return "pt-br"


def load_translations(lang: str) -> dict:
    path = os.path.join(LANG_DIR, f"{lang}.json")
    if not os.path.exists(path):
        path = os.path.join(LANG_DIR, "pt-br.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class FreezeManager:
    """Mantém um dicionário de endereços congelados e um loop que reescreve
    o valor deles continuamente, sem travar a UI."""

    def __init__(self, get_scanner):
        self._get_scanner = get_scanner
        self._frozen = {}  # addr_hex -> {"type": str, "value": float}
        self._lock = threading.Lock()
        self._thread = None
        self._running = False

    def _ensure_running(self):
        if self._thread and self._thread.is_alive():
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while self._running:
            mem_scanner = self._get_scanner()
            if mem_scanner is not None:
                with self._lock:
                    items = list(self._frozen.items())
                for addr_hex, info in items:
                    try:
                        mem_scanner.write_value(int(addr_hex, 16), info["type"], info["value"])
                    except Exception:
                        pass  # processo pode ter fechado; ignora esse ciclo
            time.sleep(FREEZE_INTERVAL)

    def toggle(self, addr_hex: str, type_str: str, value: float) -> bool:
        """Alterna o freeze de um endereço. Retorna True se ficou congelado, False se descongelou."""
        with self._lock:
            if addr_hex in self._frozen:
                del self._frozen[addr_hex]
                return False
            self._frozen[addr_hex] = {"type": type_str, "value": value}
        self._ensure_running()
        return True

    def is_frozen(self, addr_hex: str) -> bool:
        with self._lock:
            return addr_hex in self._frozen

    def clear(self):
        with self._lock:
            self._frozen.clear()

    def frozen_set(self):
        with self._lock:
            return set(self._frozen.keys())


class Api:
    def __init__(self):
        self.mem_scanner: scanner.MemoryScanner | None = None
        self.freeze = FreezeManager(lambda: self.mem_scanner)
        self.lang = load_language()

    # ---------------------------------------------------------- i18n
    def get_translations(self):
        return {
            "lang": self.lang,
            "strings": load_translations(self.lang),
        }

    # ---------------------------------------------------------- processos
    def list_processes(self):
        procs = []
        seen_pids = set()
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid in seen_pids:
                continue

            # threads de kernel (kworker, kthreadd, etc) e zumbis não têm
            # /proc/pid/exe resolvível — filtra eles pra sobrar só processos reais
            try:
                os.readlink(f"/proc/{pid}/exe")
            except OSError:
                continue

            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    name = f.read().strip()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue

            seen_pids.add(pid)
            procs.append({"pid": pid, "name": name})

        procs.sort(key=lambda p: p["name"].lower())
        return procs

    # ---------------------------------------------------------- scan
    def first_scan(self, pid: int, type_str: str, value: float):
        self.mem_scanner = scanner.MemoryScanner(pid)
        self.freeze.clear()
        rows = self.mem_scanner.first_scan(type_str, value)
        return self._rows_with_frozen(rows)

    def ai_scan(self, pid: int, value: float):
        self.mem_scanner = scanner.MemoryScanner(pid)
        self.freeze.clear()
        rows = self.mem_scanner.ai_scan(value)
        return self._rows_with_frozen(rows)

    def next_scan(self, scan_type: str, value):
        if self.mem_scanner is None:
            return []
        if value is not None and value != "":
            rows = self.mem_scanner.next_scan(scan_type, float(value))
        else:
            rows = self.mem_scanner.next_scan(scan_type)
        return self._rows_with_frozen(rows)

    def current_results(self):
        if self.mem_scanner is None:
            return []
        return self._rows_with_frozen(self.mem_scanner.current_results())

    # ---------------------------------------------------------- edição / freeze
    def write_value(self, addr_hex: str, type_str: str, value: float):
        if self.mem_scanner is None:
            raise RuntimeError("nenhum scan ativo")
        self.mem_scanner.write_value(int(addr_hex, 16), type_str, value)
        return True

    def toggle_freeze(self, addr_hex: str, type_str: str, value: float):
        return self.freeze.toggle(addr_hex, type_str, value)

    # ---------------------------------------------------------- helpers
    def _rows_with_frozen(self, rows):
        frozen = self.freeze.frozen_set()
        return [[addr, type_str, value, addr in frozen] for addr, type_str, value in rows]


if __name__ == "__main__":
    api = Api()
    webview.create_window(
        "LibraryLin",
        os.path.join(APP_DIR, "ui", "index.html"),
        js_api=api,
        width=860,
        height=620,
        background_color="#0b0f14",
    )
    webview.start()
