# LIbraryLin 📚

> [Cheat engine for your Linux]

![GitHub license](https://img.shields.io/github/license/FalkeNet/LIbraryLin)
![GitHub stars](https://img.shields.io/github/stars/FalkeNet/LIbraryLin)
![GitHub issues](https://img.shields.io/github/issues/FalkeNet/LIbraryLin)

---

## 🚀 Funcionalidades

- ✨ [Funcionalidade 1: Integração nativa com sistemas Linux]
- ⚡ [Funcionalidade 2: Alta performance e modo IA para scanner de memoria (em breve)]
- 🛠️ [Funcionalidade 3: Fácil configuração]

## 🛠️ Tecnologias Utilizadas

O projeto foi desenvolvido utilizando as seguintes tecnologias:

- **Linguagem Principal:** [Python / C++ ]
- **Dependências Chave:** [pywebview < para frontend, pybind11 < backend]
- **Ambiente Alvo:** Linux

## 📦 Instalação e Pré-requisitos

### Pré-requisitos

```bash 
pip install pybind11 --break-system-packages            
```

### Compilar C++
```bash
c++ -O3 -Wall -shared -std=c++17 -fPIC \
    $(python3 -m pybind11 --includes) \
    scanner.cpp -o scanner$(python3-config --extension-suffix)
```
Usar esse comando pode gerar algumas pedições por exemplo instalar o Python3 config, apenas use o comando que esta pedindo!

### Passo a Passo

1. **Clonar o repositório:**
   ```bash
   git clone https://github.com/FalkeNet/LIbraryLin.git
   cd LIbraryLin
