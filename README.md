# **Clique**
*A secure, elegant AI gateway for local & cloud models in your terminal.*

[![Status](https://img.shields.io/badge/Status-Active-success)](https://github.com/salo-yek/Clique)
[![License](https://img.shields.io/badge/License-MIT-blue)](https://github.com/salo-yek/Clique/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/salo-yek/Clique)
[![.NET](https://img.shields.io/badge/.NET-8.0+-purple)](https://dotnet.microsoft.com/)
[![Stars](https://img.shields.io/github/stars/salo-yek/Clique?style=social)](https://github.com/salo-yek/Clique)

---

## **✨ Features**
- **Dual AI Providers** – Seamlessly switch between **Ollama (local)** and **Mistral (cloud)**
- **Agent Mode** – AI executes tasks: shell commands, file operations, web searches, image analysis, and calculations
- **Built-in Security** – Permission manager intercepts risky actions (`Ask`, `Allow Once`, `Deny`)
- **Secure Key Storage** – Encrypted API keys via **Windows DPAPI / OS-level encryption**
- **Minimalistic CLI** – Clean, responsive terminal UI with live streaming and formatted outputs

---

## **💻 Usage**
Upon launching, Clique will auto-detect your local Ollama instance. Available commands:

| Command      | Description                          |
|--------------|--------------------------------------|
| `/help`      | Show help screen                     |
| `/mode`      | Toggle between Chat/Agent modes       |
| `/model`     | Switch between AI models             |
| `/api`       | Configure Mistral API key            |
| `/tools`     | List available AI tools               |
| `/perms`     | Manage tool permissions               |
| `/image`     | Load image for analysis               |
| `/paste`     | Enter multi-line paste mode           |
| `/clear`     | Clear chat history                    |
| `/quit`      | Exit application                      |

---

## **🔥 Tool Capabilities**
Agent Mode tools:
`execute_shell`, `read_file`, `write_file`, `delete_file`, `list_directory`,
`search_file`, `analyze_code`, `analyze_image`, `calculate`, `search_web`,
`get_env`, `system_info`

---

## **🛠️ Development & Compilation**

### **Compilation Commands**
1. **Windows**:
   ```sh
   dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true

**Minimal. Powerful. Secure.** 🚀
- *Made with love in C#* ❤️