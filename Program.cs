// Clique - A secure AI gateway for Ollama and Mistral models
// Copyright (c) 2026 saloyek
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static System.Security.Cryptography.ProtectedData;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Spectre.Console;
using Spectre.Console.Rendering;

namespace Clique
{
    public enum MessageRole
    {
        User,
        Assistant,
        System,
        Tool
    }

    public enum AppMode
    {
        Chat,
        Agent
    }

    public enum ApiProvider
    {
        Ollama,
        Mistral
    }

    public class SnakeCaseNamingPolicy : JsonNamingPolicy
    {
        public override string ConvertName(string name)
        {
            if (string.IsNullOrEmpty(name)) return name;
            var sb = new StringBuilder();
            for (int i = 0; i < name.Length; i++)
            {
                var c = name[i];
                if (char.IsUpper(c))
                {
                    if (i > 0 && sb.Length > 0 && sb[sb.Length - 1] != '_')
                        sb.Append('_');
                    sb.Append(char.ToLowerInvariant(c));
                }
                else
                {
                    sb.Append(c);
                }
            }
            var result = sb.ToString();
            while (result.Contains("__"))
                result = result.Replace("__", "_");
            return result.Trim('_');
        }
    }

    public class Message
    {
        public MessageRole Role { get; set; }
        public string Content { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string? Model { get; set; }
        public List<ToolCall>? ToolCalls { get; set; }
        public string? ToolName { get; set; }
        public string? ImageBase64 { get; set; }
    }

    public class ToolCall
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = ToolCallHelper.GenerateToolCallId();
        [JsonPropertyName("type")]
        public string Type { get; set; } = "function";
        [JsonPropertyName("function")]
        public ToolFunction Function { get; set; } = new();
    }
    
    public static class ToolCallHelper
    {
        public static string GenerateToolCallId()
        {
            // Generate a 9-character alphanumeric ID as required by the API
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            var id = new char[9];
            for (int i = 0; i < 9; i++)
                id[i] = chars[random.Next(chars.Length)];
            return new string(id);
        }
    }

    public class ToolFunction
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;
        [JsonPropertyName("arguments")]
        public string? ArgumentsString { get; set; }
        [JsonIgnore]
        public Dictionary<string, object> Arguments { get; set; } = new();
    }

    public class OMIModel
    {
        public string Name { get; set; } = string.Empty;
        public string? Size { get; set; }
        public string? ModifiedAt { get; set; }
        public string? Digest { get; set; }
        public ApiProvider Provider { get; set; } = ApiProvider.Ollama;
    }

    public class MistralModel
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;
        [JsonPropertyName("object")]
        public string Object { get; set; } = string.Empty;
        [JsonPropertyName("created")]
        public long Created { get; set; }
        [JsonPropertyName("owned_by")]
        public string OwnedBy { get; set; } = string.Empty;
    }

    public class MistralModelsResponse
    {
        [JsonPropertyName("object")]
        public string Object { get; set; } = string.Empty;
        [JsonPropertyName("data")]
        public List<MistralModel> Data { get; set; } = new();
    }

    public class SecureApiKeyStorage
    {
        private readonly string _storagePath;
        private readonly byte[] _additionalEntropy;

        public SecureApiKeyStorage(string appName = "Clique")
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var dir = Path.Combine(appData, appName);
            Directory.CreateDirectory(dir);
            _storagePath = Path.Combine(dir, "mistral_api_key.enc");
            _additionalEntropy = Encoding.UTF8.GetBytes(appName + "_entropy_v1");
        }

        public void SaveApiKey(string apiKey)
        {
            if (string.IsNullOrEmpty(apiKey))
                throw new ArgumentException("API key cannot be empty");
            var bytes = Encoding.UTF8.GetBytes(apiKey);
            var encrypted = ProtectedData.Protect(bytes, _additionalEntropy, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(_storagePath, encrypted);
        }

        public string? LoadApiKey()
        {
            if (!File.Exists(_storagePath)) return null;
            try
            {
                var encrypted = File.ReadAllBytes(_storagePath);
                var decrypted = ProtectedData.Unprotect(encrypted, _additionalEntropy, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(decrypted);
            }
            catch { return null; }
        }

        public void DeleteApiKey()
        {
            if (File.Exists(_storagePath)) File.Delete(_storagePath);
        }

        public bool HasApiKey() => File.Exists(_storagePath);
    }

    public class MistralApiService
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiKey;
        private const string BaseUrl = "https://api.mistral.ai/v1";
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public MistralApiService(string apiKey)
        {
            _apiKey = apiKey;
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_apiKey}");
        }

        public async Task<List<MistralModel>> FetchModelsAsync()
        {
            try
            {
                var response = await _httpClient.GetAsync($"{BaseUrl}/models");
                response.EnsureSuccessStatusCode();
                var content = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<MistralModelsResponse>(content, _jsonOptions);
                return result?.Data ?? new List<MistralModel>();
            }
            catch (Exception ex)
            {
                Theme.Error($"Error fetching Mistral models: {ex.Message}");
                return new List<MistralModel>();
            }
        }

        public async IAsyncEnumerable<MistralStreamChunk> ChatStreamAsync(
            string model,
            List<Message> messages,
            List<ToolDefinition>? tools = null,
            double temperature = 0.7,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var apiMessages = messages.Select(m => {
                var msg = new Dictionary<string, object>
                {
                    ["role"] = m.Role.ToString().ToLower(),
                    ["content"] = m.Content ?? ""
                };
                if (m.ToolCalls != null && m.ToolCalls.Any())
                {
                    msg["tool_calls"] = m.ToolCalls.Select(tc => new
                    {
                        id = tc.Id,
                        type = tc.Type,
                        function = new { name = tc.Function.Name, arguments = JsonSerializer.Serialize(tc.Function.Arguments) }
                    });
                }
                if (m.Role == MessageRole.Tool && !string.IsNullOrEmpty(m.ToolName))
                {
                    msg["tool_call_id"] = m.ToolName;
                }
                return msg;
            }).ToList();

            var payload = new Dictionary<string, object>
            {
                ["model"] = model,
                ["messages"] = apiMessages,
                ["temperature"] = temperature,
                ["stream"] = true
            };

            if (tools != null && tools.Any())
            {
                payload["tools"] = tools.Select(t => new
                {
                    type = "function",
                    function = new { name = t.Name, description = t.Description, parameters = t.Parameters }
                }).ToList();
            }

            var json = JsonSerializer.Serialize(payload, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, $"{BaseUrl}/chat/completions") { Content = content };
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new HttpRequestException($"Response status code does not indicate success: {(int)response.StatusCode} ({response.ReasonPhrase}). Response: {errorContent}");
            }

            await using var stream = await response.Content.ReadAsStreamAsync();
            using var reader = new StreamReader(stream, Encoding.UTF8);
            string? line;

            while ((line = await reader.ReadLineAsync().WaitAsync(cancellationToken)) != null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (!line.StartsWith("data: ")) continue;
                var data = line.Substring(6);
                if (data == "[DONE]") yield break;

                MistralStreamChunk? chunk = null;
                try { chunk = JsonSerializer.Deserialize<MistralStreamChunk>(data, _jsonOptions); }
                catch { }

                if (chunk != null) yield return chunk;
            }
        }
    }

    public class MistralStreamChunk
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;
        [JsonPropertyName("object")]
        public string Object { get; set; } = string.Empty;
        [JsonPropertyName("created")]
        public long Created { get; set; }
        [JsonPropertyName("model")]
        public string Model { get; set; } = string.Empty;
        [JsonPropertyName("choices")]
        public List<MistralChoice> Choices { get; set; } = new();
    }

    public class MistralChoice
    {
        [JsonPropertyName("index")]
        public int Index { get; set; }
        [JsonPropertyName("delta")]
        public MistralDelta Delta { get; set; } = new();
        [JsonPropertyName("finish_reason")]
        public string? FinishReason { get; set; }
    }

    public class MistralDelta
    {
        [JsonPropertyName("role")]
        public string? Role { get; set; }
        [JsonPropertyName("content")]
        public string? Content { get; set; }
        [JsonPropertyName("tool_calls")]
        public List<ToolCall>? ToolCalls { get; set; }
    }

    public class OMIApiService
    {
        private readonly HttpClient _httpClient;
        private readonly string _baseUrl;
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = new SnakeCaseNamingPolicy(),
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        private static readonly JsonSerializerOptions _deserializeOptions = new()
        {
            PropertyNamingPolicy = new SnakeCaseNamingPolicy()
        };

        public OMIApiService(string baseUrl = "http://localhost:11434")
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        }

        public async Task<List<OMIModel>> FetchModelsAsync()
        {
            try
            {
                var response = await _httpClient.GetAsync($"{_baseUrl}/api/tags");
                response.EnsureSuccessStatusCode();
                var content = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(content);
                var models = new List<OMIModel>();

                if (doc.RootElement.TryGetProperty("models", out var modelsElement))
                {
                    foreach (var model in modelsElement.EnumerateArray())
                    {
                        var name = model.GetProperty("name").GetString() ?? "";
                        var size = model.TryGetProperty("size", out var s) ? FormatBytes(s.GetInt64()) : null;
                        var modified = model.TryGetProperty("modified_at", out var m) ? m.GetString() : null;
                        models.Add(new OMIModel { Name = name, Size = size, ModifiedAt = modified, Provider = ApiProvider.Ollama });
                    }
                }
                return models;
            }
            catch { return new List<OMIModel>(); }
        }

        private static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;
            while (size >= 1024 && order < sizes.Length - 1) { order++; size /= 1024; }
            return $"{size:0.##} {sizes[order]}";
        }

        public async IAsyncEnumerable<OMIStreamChunk> ChatStreamAsync(
            string model,
            List<Message> messages,
            List<ToolDefinition>? tools = null,
            double temperature = 0.7,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var apiMessages = new List<object>();
            foreach (var m in messages)
            {
                if (m.ToolCalls != null && m.ToolCalls.Any())
                {
                    var toolCalls = m.ToolCalls.Select(tc => new
                    {
                        id = tc.Id,
                        type = tc.Type,
                        function = new { name = tc.Function.Name, arguments = tc.Function.Arguments }
                    }).ToList();

                    if (!string.IsNullOrEmpty(m.ImageBase64))
                        apiMessages.Add(new { role = m.Role.ToString().ToLower(), content = m.Content, images = new[] { m.ImageBase64 }, tool_calls = toolCalls });
                    else
                        apiMessages.Add(new { role = m.Role.ToString().ToLower(), content = m.Content, tool_calls = toolCalls });
                }
                else if (!string.IsNullOrEmpty(m.ImageBase64))
                    apiMessages.Add(new { role = m.Role.ToString().ToLower(), content = m.Content, images = new[] { m.ImageBase64 } });
                else
                    apiMessages.Add(new { role = m.Role.ToString().ToLower(), content = m.Content });
            }

            var payload = new Dictionary<string, object>
            {
                ["model"] = model,
                ["messages"] = apiMessages,
                ["stream"] = true,
                ["options"] = new { temperature }
            };

            if (tools != null && tools.Any())
            {
                payload["tools"] = tools.Select(t => new
                {
                    type = "function",
                    function = new { name = t.Name, description = t.Description, parameters = t.Parameters }
                }).ToList();
            }

            var json = JsonSerializer.Serialize(payload, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}/api/chat") { Content = content };
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new HttpRequestException($"Response status code does not indicate success: {(int)response.StatusCode} ({response.ReasonPhrase}). Response: {errorContent}");
            }

            await using var stream = await response.Content.ReadAsStreamAsync();
            using var reader = new StreamReader(stream, Encoding.UTF8);
            string? line;

            while ((line = await reader.ReadLineAsync().WaitAsync(cancellationToken)) != null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                OMIStreamChunk? chunk = null;
                try { chunk = JsonSerializer.Deserialize<OMIStreamChunk>(line, _deserializeOptions); }
                catch { }

                if (chunk != null) yield return chunk;
            }
        }
    }

    public class OMIStreamChunk
    {
        [JsonPropertyName("message")]
        public OMIMessage? Message { get; set; }
        [JsonPropertyName("done")]
        public bool Done { get; set; }
        [JsonPropertyName("tool_calls")]
        public List<ToolCall>? ToolCalls { get; set; }
    }

    public class OMIMessage
    {
        [JsonPropertyName("role")]
        public string? Role { get; set; }
        [JsonPropertyName("content")]
        public string? Content { get; set; }
        [JsonPropertyName("tool_calls")]
        public List<ToolCall>? ToolCalls { get; set; }
    }

    public class ToolDefinition
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public object Parameters { get; set; } = new();
    }

    public enum Permission { Ask, AllowOnce, AllowAlways, Deny }

    public class ToolCategory
    {
        public const string FileRead = "file_read";
        public const string FileWrite = "file_write";
        public const string FileDelete = "file_delete";
        public const string Shell = "shell";
        public const string Network = "network";
        public const string System = "system";
        public const string Other = "other";
    }

    public class PermissionManager
    {
        private readonly Dictionary<string, Permission> _toolPermissions = new();
        private readonly HashSet<string> _sessionAllowedTools = new();
        private readonly string _cwd;
        private readonly Dictionary<string, string> _toolCategories = new();

        public PermissionManager(string cwd)
        {
            _cwd = Path.GetFullPath(cwd).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).ToLower();
            InitializeToolCategories();
        }

        private void InitializeToolCategories()
        {
            _toolCategories["execute_shell"] = ToolCategory.Shell;
            _toolCategories["write_file"] = ToolCategory.FileWrite;
            _toolCategories["delete_file"] = ToolCategory.FileWrite;
            _toolCategories["read_file"] = ToolCategory.FileRead;
            _toolCategories["list_directory"] = ToolCategory.FileRead;
            _toolCategories["search_file"] = ToolCategory.FileRead;
            _toolCategories["analyze_code"] = ToolCategory.FileRead;
            _toolCategories["check_path"] = ToolCategory.FileRead;
            _toolCategories["get_env"] = ToolCategory.System;
            _toolCategories["calculate"] = ToolCategory.Other;
            _toolCategories["search_web"] = ToolCategory.Network;
            _toolCategories["system_info"] = ToolCategory.System;
            _toolCategories["analyze_image"] = ToolCategory.FileRead;
        }

        public string GetToolCategory(string toolName) =>
            _toolCategories.TryGetValue(toolName, out var category) ? category : ToolCategory.Other;

        public bool IsDangerousTool(string toolName)
        {
            var category = GetToolCategory(toolName);
            return category is ToolCategory.Shell or ToolCategory.FileWrite or ToolCategory.FileDelete;
        }

        public void SetDefaultPermissions()
        {
            foreach (var key in _toolCategories.Keys)
                _toolPermissions[key] = Permission.Ask;
        }

        public void SetPermission(string toolName, Permission permission) =>
            _toolPermissions[toolName] = permission;

        public Permission GetPermission(string toolName) =>
            _toolPermissions.TryGetValue(toolName, out var p) ? p : Permission.Ask;

        public void AllowForSession(string toolName) => _sessionAllowedTools.Add(toolName);
        public void ClearSessionPermissions() => _sessionAllowedTools.Clear();
        public void ClearAllPermissions() { _toolPermissions.Clear(); _sessionAllowedTools.Clear(); SetDefaultPermissions(); }
        public bool IsAllowedForSession(string toolName) => _sessionAllowedTools.Contains(toolName);

        public bool IsPathOutsideCwd(string path)
        {
            try
            {
                var resolved = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path))
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).ToLower();
                return !resolved.StartsWith(_cwd + Path.DirectorySeparatorChar) && resolved != _cwd;
            }
            catch { return false; }
        }

        public string GetCurrentWorkingDirectory() => _cwd;
    }

    public static class Theme
    {
        public const string Accent    = "steelblue";
        public const string User      = "springgreen3";
        public const string Tool      = "darkkhaki";
        public const string Muted     = "grey46";
        public const string Dim       = "grey35";
        public const string Warn      = "gold3_1";
        public const string Err       = "indianred";
        public const string Ok        = "darkseagreen";
        public const string Danger    = "orangered1";
        public const string Network   = "skyblue3";
        public const string System    = "mediumpurple";
        public const string Provider  = "rosybrown";

        public static string CategoryColor(string cat) => cat switch
        {
            ToolCategory.Shell      => Danger,
            ToolCategory.FileWrite  => Warn,
            ToolCategory.FileDelete => Err,
            ToolCategory.FileRead   => Accent,
            ToolCategory.Network    => Network,
            ToolCategory.System     => System,
            _                       => Muted
        };

        public static void Error(string msg)   => AnsiConsole.MarkupLine($"[{Err}]  {Esc(msg)}[/]");
        public static void LogWarn(string msg) => AnsiConsole.MarkupLine($"[{Warn}]  {Esc(msg)}[/]");
        public static void LogOk(string msg)   => AnsiConsole.MarkupLine($"[{Ok}]  {Esc(msg)}[/]");
        public static void Info(string msg)    => AnsiConsole.MarkupLine($"[{Muted}]  {Esc(msg)}[/]");
        public static void Hint(string msg)    => AnsiConsole.MarkupLine($"[{Dim}]  {Esc(msg)}[/]");

        public static string Esc(string? s)
        {
            if (s == null) return "";
            return s.Replace("[", "[[").Replace("]", "]]");
        }
    }

    public class UIService
    {
        public void ShowHeader()
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"  [bold {Theme.Accent}]Clique[/]  [grey35]AI Gateway[/]");
            Divider();
        }

        public static void Divider(string style = "grey23")
        {
            var width = Math.Min(Console.WindowWidth, 80);
            AnsiConsole.MarkupLine($"[{style}]{new string('─', width)}[/]");
        }

        public void ShowStatusBar(string model, AppMode mode, bool connected, ApiProvider provider = ApiProvider.Ollama)
        {
            var connDot  = connected ? $"[{Theme.Ok}]●[/]" : $"[{Theme.Err}]●[/]";
            var modeTag  = mode switch
            {
                AppMode.Agent => $"[{Theme.Warn}]agent[/]",
                _             => $"[{Theme.Accent}]chat[/]"
            };
            var provTag  = provider == ApiProvider.Mistral
                ? $"[{Theme.Provider}]mistral[/]"
                : $"[{Theme.Ok}]ollama[/]";

            var shortModel = model.Length > 32 ? model[..32] + "…" : model;

            AnsiConsole.MarkupLine(
                $"  {connDot}  [{Theme.Muted}]{Theme.Esc(shortModel)}[/]  [{Theme.Dim}]·[/]  {provTag}  [{Theme.Dim}]·[/]  {modeTag}");
            Divider();
        }

        public void ShowUserMessage(string content, string username)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"  [{Theme.User}]{Theme.Esc(username)}[/]  [{Theme.Muted}]{DateTime.Now:HH:mm}[/]");
            AnsiConsole.MarkupLine($"  {Theme.Esc(content)}");
        }

        public void BeginAiMessage()
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Markup($"  [{Theme.Accent}]ai[/]  [{Theme.Muted}]{DateTime.Now:HH:mm}[/]\n  ");
        }

        public void ShowAiMessage(string content)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"  [{Theme.Accent}]ai[/]  [{Theme.Muted}]{DateTime.Now:HH:mm}[/]");

            foreach (var line in content.Split('\n'))
                AnsiConsole.MarkupLine($"  {Theme.Esc(line)}");
        }

        public void ShowToolStart(string toolName)
        {
            var cat = toolName switch
            {
                "execute_shell"  => "shell",
                "write_file"     => "file_write",
                "delete_file"    => "file_delete",
                "search_web"     => "network",
                "system_info"    => "system",
                "get_env"        => "system",
                _                => "file_read"
            };
            AnsiConsole.MarkupLine(
                $"  [{Theme.Dim}]·[/] [{Theme.CategoryColor(cat)}]{Theme.Esc(toolName)}[/] [{Theme.Muted}]running[/]");
        }

        public void ShowToolResult(string toolName, bool success, string summary)
        {
            var dot   = success ? $"[{Theme.Ok}]✓[/]" : $"[{Theme.Err}]✗[/]";
            AnsiConsole.MarkupLine($"  {dot} [{Theme.Muted}]{Theme.Esc(summary)}[/]");
        }

        public void ShowThinking()
        {
            AnsiConsole.Markup($"  [{Theme.Muted}]thinking…[/]");
        }

        public string PromptInput(string username)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Markup($"  [{Theme.User}]>[/] ");
            return ReadMultiLineInput();
        }

        private static string ReadMultiLineInput()
        {
            var sb = new StringBuilder();
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    if ((key.Modifiers & ConsoleModifiers.Shift) != 0 || (key.Modifiers & ConsoleModifiers.Control) != 0)
                    {
                        sb.Append(Environment.NewLine);
                        Console.WriteLine();
                    }
                    else break;
                }
                else if (key.Key == ConsoleKey.Escape)
                {
                    Console.WriteLine();
                    return "";
                }
                else if (key.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0) { sb.Remove(sb.Length - 1, 1); Console.Write("\b \b"); }
                }
                else if (key.Key == ConsoleKey.C && (key.Modifiers & ConsoleModifiers.Control) != 0)
                {
                    Console.WriteLine();
                    return "";
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    sb.Append(key.KeyChar);
                    Console.Write(key.KeyChar);
                }
            }
            Console.WriteLine();
            return sb.ToString().Trim();
        }

        public void ShowHelp()
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"  [{Theme.Muted}]commands[/]");
            Divider("grey19");

            var cmds = new[]
            {
                ("/clear",         "clear history"),
                ("/model",         "switch model"),
                ("/mode",          "cycle chat → agent"),
                ("/paste",         "multi-line paste mode"),
                ("/image [[path]]",  "load image for vision"),
                ("/perms [[sub]]",   "tool permissions  (reset · clear-session)"),
                ("/path [[sub]]",    "manage PATH  (enable · disable · status)"),
                ("/api [[clear]]",   "configure Mistral API key"),
                ("/help",          "this screen"),
                ("/quit",          "exit"),
            };

            foreach (var (cmd, desc) in cmds)
                AnsiConsole.MarkupLine($"  [{Theme.Accent}]{cmd,-22}[/][{Theme.Muted}]{desc}[/]");

            AnsiConsole.WriteLine();
        }

        public async Task<string> ShowModelSelectorAsync(List<OMIModel> models, string currentModel, ApiProvider currentProvider)
        {
            if (!models.Any()) { Theme.LogWarn("No models available"); return currentModel; }

            var choices = new List<string>();
            var mistral = models.Where(m => m.Provider == ApiProvider.Mistral).ToList();
            var ollama  = models.Where(m => m.Provider == ApiProvider.Ollama).ToList();

            if (mistral.Any())
            {
                choices.Add("── mistral ──");
                choices.AddRange(mistral.Select(m => $"mistral: {m.Name}"));
            }
            if (ollama.Any())
            {
                choices.Add("── ollama ──");
                choices.AddRange(ollama.Select(m =>
                {
                    var s = $"{m.Name}  ({m.Size})";
                    if (m.Name == currentModel && currentProvider == ApiProvider.Ollama) s += "  ◀";
                    return s;
                }));
            }

            var selected = await AnsiConsole.PromptAsync(
                new SelectionPrompt<string>()
                    .Title($"  [{Theme.Muted}]select model[/]")
                    .PageSize(18)
                    .AddChoices(choices));

            if (selected.StartsWith("mistral: ")) return selected[9..];
            if (selected.StartsWith("──")) return currentModel;

            var idx = selected.IndexOf("  (", StringComparison.Ordinal);
            return idx >= 0 ? selected[..idx] : selected.TrimEnd('▲', ' ', '◀');
        }

        public string? PromptImagePath()
        {
            AnsiConsole.Markup($"  [{Theme.Muted}]image path (enter to cancel):[/] ");
            var path = Console.ReadLine()?.Trim();
            return string.IsNullOrEmpty(path) ? null : path;
        }

        public string PromptApiKey()
        {
            AnsiConsole.MarkupLine($"  [{Theme.Muted}]paste Mistral API key (hidden):[/]");
            AnsiConsole.Markup($"  [{Theme.User}]>[/] ");
            var key = new StringBuilder();
            while (true)
            {
                var k = Console.ReadKey(intercept: true);
                if (k.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
                if (k.Key == ConsoleKey.Backspace && key.Length > 0) { key.Remove(key.Length - 1, 1); Console.Write("\b \b"); }
                else if (!char.IsControl(k.KeyChar)) { key.Append(k.KeyChar); Console.Write("*"); }
            }
            return key.ToString().Trim();
        }

        public string PromptPermission(string toolName, string category, bool isDangerous,
                                       bool isOutsideCwd, string? targetPath, string? cmd, string cwd)
        {
            AnsiConsole.WriteLine();
            Divider("grey19");
            AnsiConsole.MarkupLine(
                $"  [{Theme.CategoryColor(category)}]{toolName}[/]  [{Theme.Muted}]{category}[/]" +
                (isDangerous ? $"  [{Theme.Danger}]dangerous[/]" : ""));

            if (targetPath != null)
                AnsiConsole.MarkupLine($"  [{Theme.Muted}]path    [/]{Theme.Esc(targetPath)}");
            if (cmd != null)
            {
                var display = cmd.Length > 72 ? cmd[..72] + "…" : cmd;
                AnsiConsole.MarkupLine($"  [{Theme.Muted}]command [/]{Theme.Esc(display)}");
            }
            if (isOutsideCwd)
            {
                AnsiConsole.MarkupLine($"  [{Theme.Danger}]! outside cwd[/]  [{Theme.Muted}]{Theme.Esc(cwd)}[/]");
            }

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"  [{Theme.Accent}]a[/] allow once   [{Theme.Accent}]s[/] session   [{Theme.Err}]d[/] deny   [{Theme.Err}]n[/] never");
            AnsiConsole.Markup($"  [{Theme.User}]>[/] ");
            Console.Out.Flush();

            return Console.ReadLine()?.Trim().ToLower() ?? "";
        }

        public static string EscapeMarkup(string text) => Theme.Esc(text);
    }

    public class ToolKitService
    {
        private readonly Dictionary<string, (object Result, DateTime Timestamp)> _cache = new();
        private readonly int _cacheTtl;

        public ToolKitService(int cacheTtl = 300) { _cacheTtl = cacheTtl; }
        public void ClearCache() => _cache.Clear();

        private string GetCacheKey(string toolName, Dictionary<string, object> parameters)
        {
            var paramStr = JsonSerializer.Serialize(parameters);
            var hash = MD5.HashData(Encoding.UTF8.GetBytes($"{toolName}:{paramStr}"));
            return Convert.ToHexString(hash).ToLower();
        }

        private object? GetCached(string key)
        {
            if (_cache.TryGetValue(key, out var cached) && (DateTime.Now - cached.Timestamp).TotalSeconds < _cacheTtl)
                return cached.Result;
            return null;
        }

        private void SetCached(string key, object result) => _cache[key] = (result, DateTime.Now);

        private static string SafePath(string path)
        {
            var expanded = Environment.ExpandEnvironmentVariables(path);
            var resolved = Path.GetFullPath(expanded);
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var cwd  = Environment.CurrentDirectory;
            var resolvedNorm = Path.GetFullPath(resolved).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var homeNorm     = Path.GetFullPath(home).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var cwdNorm      = Path.GetFullPath(cwd).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            bool inHome = resolvedNorm.StartsWith(homeNorm + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                       || resolvedNorm.Equals(homeNorm, StringComparison.OrdinalIgnoreCase);
            bool inCwd  = resolvedNorm.StartsWith(cwdNorm + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                       || resolvedNorm.Equals(cwdNorm, StringComparison.OrdinalIgnoreCase);
            if (!inHome && !inCwd)
                throw new ArgumentException($"Path {path} escapes allowed directories");
            return resolved;
        }

        public Dictionary<string, object> ReadFile(string path)
        {
            var cacheKey = GetCacheKey("read_file", new() { ["path"] = path });
            var cached = GetCached(cacheKey);
            if (cached != null) return new Dictionary<string, object>((Dictionary<string, object>)cached) { ["cached"] = true };
            try
            {
                var fullPath = SafePath(path);
                if (!File.Exists(fullPath)) return new Dictionary<string, object> { ["error"] = $"File not found: {path}" };
                var content = File.ReadAllText(fullPath, Encoding.UTF8);
                var originalSize = content.Length;
                const int maxSize = 10000;
                var truncated = originalSize > maxSize;
                if (truncated) content = content[..maxSize];
                var result = new Dictionary<string, object> { ["content"] = content, ["size"] = originalSize, ["path"] = fullPath, ["truncated"] = truncated };
                if (truncated) result["note"] = $"File truncated ({maxSize}/{originalSize} bytes)";
                SetCached(cacheKey, result);
                return result;
            }
            catch (Exception e) { return new Dictionary<string, object> { ["error"] = e.Message }; }
        }

        public Dictionary<string, object> WriteFile(string path, string content)
        {
            try
            {
                var fullPath = SafePath(path);
                var dangerous = new[] { ".git", "node_modules", ".venv", "venv", "__pycache__", ".env" };
                var pathParts = fullPath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (dangerous.Any(d => pathParts.Contains(d)))
                    return new Dictionary<string, object> { ["error"] = "Writing to protected directory not allowed" };
                var dir = Path.GetDirectoryName(fullPath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(fullPath, content, Encoding.UTF8);
                _cache.Remove(GetCacheKey("read_file", new() { ["path"] = path }));
                return new Dictionary<string, object> { ["success"] = true, ["path"] = fullPath, ["bytes_written"] = content.Length };
            }
            catch (Exception e) { return new Dictionary<string, object> { ["error"] = e.Message }; }
        }

        public Dictionary<string, object> ListDirectory(string path = ".")
        {
            var cacheKey = GetCacheKey("list_directory", new() { ["path"] = path });
            var cached = GetCached(cacheKey);
            if (cached != null) return new Dictionary<string, object>((Dictionary<string, object>)cached) { ["cached"] = true };
            try
            {
                var fullPath = SafePath(path);
                if (!Directory.Exists(fullPath)) return new Dictionary<string, object> { ["error"] = $"Not a directory: {path}" };
                var items = Directory.GetFileSystemEntries(fullPath);
                var files = new List<Dictionary<string, object>>();
                var dirs  = new List<Dictionary<string, object>>();
                foreach (var item in items)
                {
                    try
                    {
                        var info = new FileInfo(item);
                        var dict = new Dictionary<string, object> { ["name"] = Path.GetFileName(item), ["modified"] = info.LastWriteTime.ToString("yyyy-MM-dd HH:mm") };
                        if (Directory.Exists(item)) { dict["type"] = "directory"; dirs.Add(dict); }
                        else { dict["type"] = "file"; dict["size"] = FormatFileSize(info.Length); files.Add(dict); }
                    }
                    catch { continue; }
                }
                var result = new Dictionary<string, object> { ["path"] = fullPath, ["directories"] = dirs.OrderBy(d => d["name"]).ToList(), ["files"] = files.OrderBy(f => f["name"]).ToList(), ["total"] = items.Length };
                SetCached(cacheKey, result);
                return result;
            }
            catch (Exception e) { return new Dictionary<string, object> { ["error"] = e.Message }; }
        }

        private static string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
            int order = 0; double size = bytes;
            while (size >= 1024 && order < sizes.Length - 1) { order++; size /= 1024; }
            return $"{size:0.##} {sizes[order]}";
        }

        public async Task<Dictionary<string, object>> ExecuteShell(string command)
        {
            var dangerous = new[] { @"rm\s+-rf\s+/", @":\(\)\{\s*:\|:\&\s*\};:", @">\s*/dev/(null|zero|random|urandom)", @"curl\s+.*\|\s*sh", @"wget\s+.*\s*-O\s*-\s*\|\s*sh", @"mkfs", @"dd\s+if=", @">\s*/etc/", @";\s*rm\s+", @"\brm\s+-rf\s+\$" };
            foreach (var pattern in dangerous)
                if (Regex.IsMatch(command, pattern, RegexOptions.IgnoreCase))
                    return new Dictionary<string, object> { ["error"] = "Command blocked by security policy", ["success"] = false };
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "cmd.exe" : "/bin/bash",
                    Arguments = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? $"/c {command}" : $"-c \"{command.Replace("\"", "\\\"")}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = Environment.CurrentDirectory
                };
                using var process = Process.Start(psi);
                if (process == null) return new Dictionary<string, object> { ["error"] = "Failed to start process", ["success"] = false };
                var stdoutTask = process.StandardOutput.ReadToEndAsync();
                var stderrTask = process.StandardError.ReadToEndAsync();
                var timeoutTask = Task.Delay(30000);
                var exitTask = Task.Run(() => { process.WaitForExit(); return true; });
                if (await Task.WhenAny(exitTask, timeoutTask) == timeoutTask)
                {
                    try { process.Kill(); } catch { }
                    return new Dictionary<string, object> { ["error"] = "Command timed out after 30s", ["success"] = false };
                }
                var stdout = await stdoutTask;
                var stderr = await stderrTask;
                return new Dictionary<string, object>
                {
                    ["stdout"] = string.IsNullOrEmpty(stdout) ? "(no output)" : stdout[..Math.Min(stdout.Length, 2000)],
                    ["stderr"] = string.IsNullOrEmpty(stderr) ? "(no errors)" : stderr[..Math.Min(stderr.Length, 1000)],
                    ["exit_code"] = process.ExitCode,
                    ["success"] = process.ExitCode == 0
                };
            }
            catch (Exception e) { return new Dictionary<string, object> { ["error"] = e.Message, ["success"] = false }; }
        }

        public Dictionary<string, object> SystemInfo()
        {
            var cacheKey = "system_info";
            var cached = GetCached(cacheKey);
            if (cached != null) return new Dictionary<string, object>((Dictionary<string, object>)cached) { ["cached"] = true };
            var result = new Dictionary<string, object> { ["platform"] = RuntimeInformation.OSDescription, ["architecture"] = RuntimeInformation.ProcessArchitecture.ToString(), ["hostname"] = Environment.MachineName, ["username"] = Environment.UserName, ["cwd"] = Environment.CurrentDirectory, ["dotnet_version"] = Environment.Version.ToString() };
            SetCached(cacheKey, result);
            return result;
        }

        public Dictionary<string, object> SearchFile(string path, string searchTerm)
        {
            try
            {
                var fullPath = SafePath(path);
                if (!File.Exists(fullPath)) return new Dictionary<string, object> { ["error"] = $"File not found: {path}" };
                var lines = File.ReadAllLines(fullPath, Encoding.UTF8);
                var results = new List<Dictionary<string, object>>();
                var pattern = new Regex(Regex.Escape(searchTerm), RegexOptions.IgnoreCase);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (pattern.IsMatch(lines[i]))
                    {
                        results.Add(new Dictionary<string, object> { ["line"] = i + 1, ["content"] = lines[i].TrimEnd(), ["context"] = GetLineContext(lines, i) });
                    }
                }
                return new Dictionary<string, object> { ["search_term"] = searchTerm, ["matches"] = results.Count, ["results"] = results.Take(50).ToList(), ["file"] = fullPath };
            }
            catch (Exception e) { return new Dictionary<string, object> { ["error"] = e.Message }; }
        }

        private static string GetLineContext(string[] lines, int index)
        {
            var sb = new StringBuilder();
            if (index > 0) sb.AppendLine($"  {index}: {lines[index - 1].Trim()}");
            sb.AppendLine($"> {index + 1}: {lines[index].Trim()}");
            if (index < lines.Length - 1) sb.AppendLine($"  {index + 2}: {lines[index + 1].Trim()}");
            return sb.ToString();
        }

        public Dictionary<string, object> AnalyzeCode(string path)
        {
            try
            {
                var fullPath = SafePath(path);
                if (!File.Exists(fullPath)) return new Dictionary<string, object> { ["error"] = $"File not found: {path}" };
                var content = File.ReadAllText(fullPath, Encoding.UTF8);
                var lines = content.Split('\n');
                var ext = Path.GetExtension(fullPath).ToLower();
                var analysis = new Dictionary<string, object>
                {
                    ["file"] = fullPath,
                    ["language"] = ext,
                    ["total_lines"] = lines.Length,
                    ["code_lines"] = lines.Count(l => !string.IsNullOrWhiteSpace(l) && !l.Trim().StartsWith("//")),
                    ["blank_lines"] = lines.Count(string.IsNullOrWhiteSpace),
                    ["comment_lines"] = lines.Count(l => l.Trim().StartsWith("//") || l.Trim().StartsWith("#")),
                };
                if (ext == ".cs")
                {
                    analysis["classes"] = lines.Count(l => Regex.IsMatch(l.Trim(), @"^\s*(public|private|internal)?\s*class\s+"));
                    analysis["methods"] = lines.Count(l => Regex.IsMatch(l.Trim(), @"^\s*(public|private|protected|internal)\s+.*\(.*\)"));
                    analysis["imports"] = lines.Count(l => l.Trim().StartsWith("using "));
                }
                return analysis;
            }
            catch (Exception e) { return new Dictionary<string, object> { ["error"] = e.Message }; }
        }

        public Dictionary<string, object> AnalyzeImage(string path)
        {
            var cacheKey = GetCacheKey("analyze_image", new() { ["path"] = path });
            var cached = GetCached(cacheKey);
            if (cached != null) return new Dictionary<string, object>((Dictionary<string, object>)cached) { ["cached"] = true };
            try
            {
                var fullPath = SafePath(path);
                if (!File.Exists(fullPath)) return new Dictionary<string, object> { ["error"] = $"File not found: {path}" };
                var ext = Path.GetExtension(fullPath).ToLower();
                var imageExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".tiff", ".tif" };
                if (!imageExtensions.Contains(ext)) return new Dictionary<string, object> { ["error"] = "Not an image file" };
                var imageBytes = File.ReadAllBytes(fullPath);
                var base64 = Convert.ToBase64String(imageBytes);
                var mimeType = ext switch { ".jpg" or ".jpeg" => "image/jpeg", ".png" => "image/png", ".gif" => "image/gif", ".bmp" => "image/bmp", ".webp" => "image/webp", ".ico" => "image/x-icon", ".tiff" or ".tif" => "image/tiff", _ => "application/octet-stream" };
                var dataUrl = $"data:{mimeType};base64,{base64}";
                var result = new Dictionary<string, object> { ["path"] = fullPath, ["filename"] = Path.GetFileName(fullPath), ["format"] = mimeType, ["size_bytes"] = imageBytes.Length, ["width"] = 0, ["height"] = 0, ["base64"] = dataUrl, ["ready_for_vision"] = true };
                try { using var ms = new MemoryStream(imageBytes); using var img = System.Drawing.Image.FromStream(ms); result["width"] = img.Width; result["height"] = img.Height; }
                catch { }
                SetCached(cacheKey, result);
                return result;
            }
            catch (Exception e) { return new Dictionary<string, object> { ["error"] = e.Message }; }
        }

        public Dictionary<string, object> CheckPath(string path)
        {
            try
            {
                var fullPath = SafePath(path);
                var exists = File.Exists(fullPath) || Directory.Exists(fullPath);
                if (!exists) return new Dictionary<string, object> { ["exists"] = false, ["path"] = path };
                var info = new FileInfo(fullPath);
                var result = new Dictionary<string, object> { ["exists"] = true, ["path"] = fullPath, ["is_file"] = File.Exists(fullPath), ["is_directory"] = Directory.Exists(fullPath), ["created"] = info.CreationTime.ToString("yyyy-MM-dd HH:mm"), ["modified"] = info.LastWriteTime.ToString("yyyy-MM-dd HH:mm") };
                if (File.Exists(fullPath)) { result["size"] = info.Length; result["extension"] = Path.GetExtension(fullPath); }
                return result;
            }
            catch (Exception e) { return new Dictionary<string, object> { ["error"] = e.Message }; }
        }

        public Dictionary<string, object> GetEnv(string varName = "")
        {
            try
            {
                if (!string.IsNullOrEmpty(varName))
                {
                    var value = Environment.GetEnvironmentVariable(varName);
                    return value == null ? new Dictionary<string, object> { ["error"] = $"Variable not found: {varName}" } : new Dictionary<string, object> { [varName] = value.Length > 500 ? value[..500] + "..." : value };
                }
                var important = new[] { "PATH", "HOME", "USER", "SHELL", "PWD" };
                var env = new Dictionary<string, object>();
                foreach (var v in important) { var val = Environment.GetEnvironmentVariable(v); if (val != null) env[v] = val.Length > 200 ? val[..200] + "..." : val; }
                return env;
            }
            catch (Exception e) { return new Dictionary<string, object> { ["error"] = e.Message }; }
        }

        public Dictionary<string, object> Calculate(string expression)
        {
            try
            {
                var allowed = @"^[0-9+\-*/().\s]+$";
                if (!Regex.IsMatch(expression, allowed)) return new Dictionary<string, object> { ["error"] = "Expression contains disallowed characters" };
                var table = new DataTable();
                var result = table.Compute(expression, "");
                return new Dictionary<string, object> { ["expression"] = expression, ["result"] = result?.ToString() ?? "", ["type"] = result?.GetType().Name ?? "" };
            }
            catch (Exception e) { return new Dictionary<string, object> { ["error"] = $"Calculation error: {e.Message}" }; }
        }

        public async Task<Dictionary<string, object>> SearchWebAsync(string query, int numResults = 5)
        {
            var encoded = Uri.EscapeDataString(query);
            var errors  = new List<string>();

            var searchConfigs = new[]
            {
                new { Name = "duckduckgo_lite", Url = $"https://lite.duckduckgo.com/lite/?q={encoded}&kl=en-us", Pattern = @"<a[^>]+href=""([^""]+)""[^>]*class=""[^""]*result-link[^""]*""[^>]*>([^<]+)</a>" },
                new { Name = "duckduckgo_html", Url = $"https://html.duckduckgo.com/html/?q={encoded}&kl=en-us", Pattern = @"<a[^>]+class=""result__a""[^>]+href=""([^""]+)""[^>]*>([^<]+)</a>" },
                new { Name = "startpage", Url = $"https://www.startpage.com/do/search?q={encoded}", Pattern = @"<a[^>]+class=""[^""]*result[^""]*""[^>]*href=""([^""]+)""[^>]*>([^<]+)</a>" },
                new { Name = "bing_html", Url = $"https://www.bing.com/search?q={encoded}&form=QBLH", Pattern = @"<a[^>]+href=""([^""]+)""[^>]*class=""[^""]*title[^""]*""[^>]*>([^<]+)</a>" },
                new { Name = "google_html", Url = $"https://www.google.com/search?q={encoded}&hl=en", Pattern = @"<a[^>]+href=""/url\?q=([^&""]+)""[^>]*>([^<]+)</a>" },
                new { Name = "yahoo", Url = $"https://search.yahoo.com/search?p={encoded}", Pattern = @"<a[^>]+href=""([^""]+)""[^>]*class=""[^""]*title[^""]*""[^>]*>([^<]+)</a>" },
                new { Name = "searx", Url = $"https://searx.be/search?q={encoded}", Pattern = @"<a[^>]+class=""result_url[^""]*""[^>]*href=""([^""]+)""[^>]*>" }
            };

            foreach (var config in searchConfigs)
            {
                try
                {
                    using var handler = new HttpClientHandler { UseCookies = true, AllowAutoRedirect = true };
                    using var client  = new HttpClient(handler);
                    client.Timeout = TimeSpan.FromSeconds(15);
                    client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36");
                    client.DefaultRequestHeaders.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
                    client.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");
                    client.DefaultRequestHeaders.Add("Referer", "https://www.google.com/");
                    await Task.Delay(Random.Shared.Next(200, 800));
                    using var response = await client.GetAsync(config.Url);
                    if (!response.IsSuccessStatusCode) { errors.Add($"[{config.Name}] HTTP {(int)response.StatusCode}"); continue; }
                    var html = await response.Content.ReadAsStringAsync();
                    if (string.IsNullOrWhiteSpace(html) || html.Length < 200) { errors.Add($"[{config.Name}] Empty response"); continue; }
                    var results = new List<Dictionary<string, object>>();
                    var patterns = new[] { config.Pattern, @"<a[^>]+href=""([^""]+)""[^>]*>([^<]+)</a>", @"<a[^>]+href=""/url\?q=([^&""]+)""[^>]*>([^<]+)</a>" };
                    foreach (var pattern in patterns)
                    {
                        foreach (Match match in Regex.Matches(html, pattern, RegexOptions.Singleline | RegexOptions.IgnoreCase))
                        {
                            if (results.Count >= numResults) break;
                            string href  = match.Groups[1].Value;
                            string title = match.Groups.Count > 2 ? match.Groups[2].Value : "Untitled";
                            if (href.Contains("uddg=")) { var m2 = Regex.Match(href, @"uddg=([^&]+)"); if (m2.Success) href = Uri.UnescapeDataString(m2.Groups[1].Value); }
                            else if (href.Contains("/url?q=")) { var m2 = Regex.Match(href, @"/url\?q=([^&]+)"); if (m2.Success) href = Uri.UnescapeDataString(m2.Groups[1].Value); }
                            if (!string.IsNullOrWhiteSpace(href) && (href.StartsWith("http") || href.StartsWith("https")) &&
                                !href.Contains("duckduckgo.com") && !href.Contains("bing.com") && !href.Contains("google.com") &&
                                title.Length > 3 && !results.Any(r => r["url"].ToString() == href))
                                results.Add(new Dictionary<string, object> { ["title"] = WebUtility.HtmlDecode(title.Trim()), ["url"] = href.Trim() });
                        }
                        if (results.Count >= numResults) break;
                    }
                    if (results.Count > 0)
                        return new Dictionary<string, object> { ["query"] = query, ["results"] = results, ["count"] = results.Count, ["engine"] = config.Name };
                }
                catch (Exception e) { errors.Add($"[{config.Name}] {e.Message}"); }
            }

            return new Dictionary<string, object>
            {
                ["error"] = "Web search failed. All search engines blocked the request.",
                ["details"] = errors.Take(5).ToList(),
                ["suggestion"] = "Configure an API key (SerpAPI, Bing API, etc.) for reliable search.",
                ["browser_fallback_available"] = true
            };
        }

        public async Task<Dictionary<string, object>> AskForBrowserFallbackAsync(string query)
        {
            Theme.LogWarn("All search engines failed. Open browser to search?");
            AnsiConsole.MarkupLine($"  [{Theme.Accent}]y[/] open browser   [{Theme.Err}]n[/] cancel");
            AnsiConsole.Markup($"  [{Theme.User}]>[/] ");

            var input = Console.ReadLine()?.Trim().ToLower();
            if (input != "y")
                return new Dictionary<string, object> { ["error"] = "Web search blocked", ["suggestion"] = "Try your browser manually." };

            try
            {
                Process.Start(new ProcessStartInfo { FileName = $"https://duckduckgo.com/?q={Uri.EscapeDataString(query)}&kl=en-us", UseShellExecute = true });
                Theme.Info("Browser opened. Press Enter when done, or type 'paste' to paste results.");
                var pasteInput = Console.ReadLine()?.Trim().ToLower();
                if (pasteInput == "paste")
                {
                    Theme.Info("Paste results, then type 'paste' on a new line to send:");
                    var sb = new StringBuilder();
                    string? line;
                    while ((line = Console.ReadLine()) != null) { if (line.Trim().Equals("paste", StringComparison.OrdinalIgnoreCase)) break; sb.AppendLine(line); }
                    var pasted = sb.ToString();
                    if (!string.IsNullOrWhiteSpace(pasted))
                        return new Dictionary<string, object> { ["query"] = query, ["results"] = new List<Dictionary<string, object>>(), ["count"] = 0, ["engine"] = "manual_paste", ["content"] = pasted, ["note"] = "Pasted manually by user" };
                }
                return new Dictionary<string, object> { ["query"] = query, ["results"] = new List<Dictionary<string, object>>(), ["count"] = 0, ["engine"] = "browser_manual", ["note"] = "User searched manually in browser" };
            }
            catch (Exception ex) { return new Dictionary<string, object> { ["error"] = $"Failed to open browser: {ex.Message}" }; }
        }
    }

    class Program
    {
        private static OMIApiService?    _apiService;
        private static MistralApiService? _mistralService;
        private static ToolKitService?   _toolKit;
        private static UIService?        _ui;
        private static PermissionManager? _permissionManager;
        private static SecureApiKeyStorage? _apiKeyStorage;
        private static CancellationTokenSource? _cts;
        private static string   _selectedModel   = "cogito-2.1:671b-cloud";
        private static AppMode  _currentMode     = AppMode.Agent;
        private static ApiProvider _currentProvider = ApiProvider.Ollama;
        private static List<Message>   _messages        = new();
        private static List<OMIModel>  _availableModels = new();
        private static bool     _isGenerating    = false;
        private static string   _userName        = Environment.UserName;
        private static bool     _statusBarNeedsUpdate = true;
        private static string?  _pendingImageBase64;

        static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding  = Encoding.UTF8;

            _apiService        = new OMIApiService();
            _toolKit           = new ToolKitService();
            _ui                = new UIService();
            _permissionManager = new PermissionManager(Environment.CurrentDirectory);
            _permissionManager.SetDefaultPermissions();
            _apiKeyStorage     = new SecureApiKeyStorage();

            _ui.ShowHeader();
            await InitializeAsync();

            while (true)
            {
                if (_statusBarNeedsUpdate)
                {
                    _ui.ShowStatusBar(_selectedModel, _currentMode, IsConnected(), _currentProvider);
                    _statusBarNeedsUpdate = false;
                }

                var input = _ui.PromptInput(_userName);
                if (string.IsNullOrEmpty(input)) continue;

                if (input.StartsWith("/"))
                    await HandleCommandAsync(input);
                else
                    await SendMessageAsync(input);
            }
        }

        private static bool IsConnected()
        {
            if (_currentProvider == ApiProvider.Mistral) return _mistralService != null;
            return _availableModels.Any(m => m.Provider == ApiProvider.Ollama);
        }

        private static async Task InitializeAsync()
        {
            await AnsiConsole.Status().StartAsync("connecting…", async ctx =>
            {
                var ollamaModels = await _apiService!.FetchModelsAsync();
                _availableModels.AddRange(ollamaModels);
            });

            await LoadMistralModelsAsync();

            if (_availableModels.Any())
            {
                OMIModel? defaultModel = null;
                var mistralDefault = _availableModels.FirstOrDefault(m => m.Provider == ApiProvider.Mistral && string.Equals(m.Name, "codestral-latest", StringComparison.OrdinalIgnoreCase));
                if (mistralDefault != null) { defaultModel = mistralDefault; _currentProvider = ApiProvider.Mistral; }
                else
                {
                    defaultModel = _availableModels.FirstOrDefault(m => m.Provider == ApiProvider.Ollama && string.Equals(m.Name, "cogito-2.1:671b-cloud", StringComparison.OrdinalIgnoreCase))
                        ?? _availableModels.FirstOrDefault(m => m.Provider == ApiProvider.Ollama && m.Name.Contains("cogito", StringComparison.OrdinalIgnoreCase))
                        ?? _availableModels.FirstOrDefault(m => m.Provider == ApiProvider.Ollama && m.Name.Contains("kimi-k2.5", StringComparison.OrdinalIgnoreCase))
                        ?? _availableModels.FirstOrDefault(m => m.Provider == ApiProvider.Ollama && m.Name.Contains("llama", StringComparison.OrdinalIgnoreCase))
                        ?? _availableModels.FirstOrDefault(m => m.Provider == ApiProvider.Ollama);
                }
                if (defaultModel != null) _selectedModel = defaultModel.Name;

                Theme.LogOk($"{_availableModels.Count(m => m.Provider == ApiProvider.Ollama)} ollama models");
                if (_availableModels.Any(m => m.Provider == ApiProvider.Mistral))
                    Theme.LogOk($"{_availableModels.Count(m => m.Provider == ApiProvider.Mistral)} mistral models");
            }
            else
            {
                Theme.LogWarn("ollama not responding — is it running?");
                Theme.Hint("try: ollama serve");
            }

            _ui!.ShowHelp();
        }

        private static async Task LoadMistralModelsAsync()
        {
            var apiKey = _apiKeyStorage!.LoadApiKey();
            if (!string.IsNullOrEmpty(apiKey))
            {
                try
                {
                    _mistralService = new MistralApiService(apiKey);
                    var models = await _mistralService.FetchModelsAsync();
                    foreach (var m in models)
                        _availableModels.Add(new OMIModel { Name = m.Id, Provider = ApiProvider.Mistral, Size = "cloud", ModifiedAt = DateTimeOffset.FromUnixTimeSeconds(m.Created).ToString("yyyy-MM-dd") });
                }
                catch (Exception ex) { Theme.LogWarn($"Failed to load Mistral models: {ex.Message}"); }
            }
        }

        private static async Task HandleCommandAsync(string command)
        {
            var parts = command.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            var cmd   = parts[0].ToLower();

            switch (cmd)
            {
                case "/quit":
                case "/exit":
                    Theme.Info("bye.");
                    Environment.Exit(0);
                    break;

                case "/clear":
                    _messages.Clear();
                    _toolKit!.ClearCache();
                    AnsiConsole.Clear();
                    _ui!.ShowHeader();
                    Theme.Info("history cleared");
                    _statusBarNeedsUpdate = true;
                    break;

                case "/model":
                    var newModel = await _ui!.ShowModelSelectorAsync(_availableModels, _selectedModel, _currentProvider);
                    if (newModel != _selectedModel || true)
                    {
                        _selectedModel = newModel;
                        var modelObj = _availableModels.FirstOrDefault(m => m.Name == _selectedModel);
                        if (modelObj != null) _currentProvider = modelObj.Provider;
                        Theme.LogOk($"model → {_selectedModel}");
                        _statusBarNeedsUpdate = true;
                    }
                    break;

                case "/mode":
                    ToggleMode();
                    break;

                case "/tools":
                    ShowTools();
                    break;

                case "/help":
                    _ui!.ShowHelp();
                    break;

                case "/image":
                    await HandleImageCommandAsync(parts);
                    break;

                case "/perms":
                    if (parts.Length > 1)
                    {
                        switch (parts[1].ToLower())
                        {
                            case "reset":         _permissionManager!.ClearAllPermissions();    Theme.LogOk("permissions reset"); break;
                            case "clear-session": _permissionManager!.ClearSessionPermissions(); Theme.LogOk("session permissions cleared"); break;
                            default: Theme.Error("unknown subcommand  (reset · clear-session)"); break;
                        }
                    }
                    else ShowPermissions();
                    break;

                case "/path":
                    HandlePathCommand(parts);
                    break;

                case "/api":
                    await HandleApiCommandAsync(parts);
                    break;

                case "/paste":
                    await HandlePasteAsync();
                    break;

                default:
                    Theme.Error($"unknown command: {cmd}");
                    break;
            }
        }

        private static async Task HandleApiCommandAsync(string[] parts)
        {
            if (parts.Length > 1 && parts[1].ToLower() == "clear")
            {
                _apiKeyStorage!.DeleteApiKey();
                _mistralService = null;
                _availableModels.RemoveAll(m => m.Provider == ApiProvider.Mistral);
                Theme.LogOk("Mistral API key removed");
                if (_currentProvider == ApiProvider.Mistral)
                {
                    _currentProvider = ApiProvider.Ollama;
                    var m = _availableModels.FirstOrDefault(x => x.Provider == ApiProvider.Ollama);
                    _selectedModel = m?.Name ?? "cogito-2.1:671b-cloud";
                    _statusBarNeedsUpdate = true;
                }
                return;
            }

            var apiKey = _ui!.PromptApiKey();
            if (string.IsNullOrEmpty(apiKey)) { Theme.LogWarn("cancelled"); return; }

            try
            {
                _apiKeyStorage!.SaveApiKey(apiKey);
                _mistralService = new MistralApiService(apiKey);
                var models = await _mistralService.FetchModelsAsync();

                if (models.Any())
                {
                    Theme.LogOk($"API key saved — {models.Count} Mistral models found");
                    _availableModels.RemoveAll(m => m.Provider == ApiProvider.Mistral);
                    foreach (var m in models)
                        _availableModels.Add(new OMIModel { Name = m.Id, Provider = ApiProvider.Mistral, Size = "cloud", ModifiedAt = DateTimeOffset.FromUnixTimeSeconds(m.Created).ToString("yyyy-MM-dd") });

                    var codestral = models.FirstOrDefault(m => m.Id.Equals("codestral-latest", StringComparison.OrdinalIgnoreCase));
                    if (codestral != null) { _selectedModel = "codestral-latest"; _currentProvider = ApiProvider.Mistral; Theme.LogOk("default → codestral-latest"); }
                    Theme.Hint("use /model to switch");
                }
                else Theme.LogWarn("key saved but no models found — key may be invalid");
            }
            catch (Exception ex)
            {
                Theme.Error($"validation failed: {ex.Message}");
                Theme.Hint("key was not saved");
            }
        }

        private static async Task HandleImageCommandAsync(string[] parts)
        {
            var imagePath = parts.Length > 1 ? parts[1] : _ui!.PromptImagePath();
            if (string.IsNullOrEmpty(imagePath)) { Theme.Info("cancelled"); return; }

            var result = _toolKit!.AnalyzeImage(imagePath);
            if (result.ContainsKey("error")) { Theme.Error(result["error"].ToString()!); return; }

            if (result.TryGetValue("base64", out var b64))
            {
                _pendingImageBase64 = b64?.ToString();
                var w = result.TryGetValue("width",  out var w2) ? w2 : 0;
                var h = result.TryGetValue("height", out var h2) ? h2 : 0;
                var f = result.TryGetValue("filename", out var f2) ? f2?.ToString() : imagePath;
                var s = result.TryGetValue("size_bytes", out var s2) ? s2 : 0;
                Theme.LogOk($"image loaded: {f}  {w}×{h}  {s} bytes");
                Theme.Hint("type your message to analyze, or press Enter for auto-description");
            }
        }

        private static async Task HandlePasteAsync()
        {
            Theme.Info("paste mode — type /paste on a new line to send");
            var sb = new StringBuilder();
            while (true)
            {
                var line = Console.ReadLine();
                if (line == null) break;
                if (line.Trim().Equals("/paste", StringComparison.OrdinalIgnoreCase)) break;
                sb.AppendLine(line);
            }
            var text = sb.ToString().Trim();
            if (!string.IsNullOrEmpty(text)) await SendMessageAsync(text);
        }

        private static void HandlePathCommand(string[] parts)
        {
            var exePath = Environment.ProcessPath ?? "";
            if (string.IsNullOrEmpty(exePath)) { Theme.Error("could not determine OMI executable path"); return; }

            var exeDir    = Path.GetDirectoryName(exePath) ?? "";
            var userPath  = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User) ?? "";
            var pathParts = userPath.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
            var isInPath  = pathParts.Any(p => string.Equals(Path.GetFullPath(p).TrimEnd(Path.DirectorySeparatorChar), Path.GetFullPath(exeDir).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase));

            if (parts.Length == 1)
            {
                var status = isInPath ? $"[{Theme.Ok}]enabled[/]" : $"[{Theme.Warn}]disabled[/]";
                AnsiConsole.MarkupLine($"  PATH {status}  [{Theme.Muted}]{exePath}[/]");
                if (!isInPath) Theme.Hint("run /path enable to add to PATH");
                return;
            }

            switch (parts[1].ToLower())
            {
                case "status":
                    AnsiConsole.MarkupLine($"  [{Theme.Muted}]status      [/]{(isInPath ? $"[{Theme.Ok}]enabled[/]" : $"[{Theme.Warn}]disabled[/]")}");
                    AnsiConsole.MarkupLine($"  [{Theme.Muted}]executable  [/]{exePath}");
                    AnsiConsole.MarkupLine($"  [{Theme.Muted}]directory   [/]{exeDir}");
                    break;

                case "enable":
                    if (isInPath) { Theme.Info("already in PATH"); return; }
                    var newPath = string.IsNullOrEmpty(userPath) ? exeDir : userPath + Path.PathSeparator + exeDir;
                    try { Environment.SetEnvironmentVariable("PATH", newPath, EnvironmentVariableTarget.User); Theme.LogOk($"added to PATH: {exeDir}"); Theme.Hint("restart terminal for changes to take effect"); }
                    catch (Exception ex) { Theme.Error($"failed: {ex.Message}"); }
                    break;

                case "disable":
                case "remove":
                    if (!isInPath) { Theme.Info("not in PATH"); return; }
                    var updatedPath = string.Join(Path.PathSeparator.ToString(), pathParts.Where(p => !string.Equals(Path.GetFullPath(p).TrimEnd(Path.DirectorySeparatorChar), Path.GetFullPath(exeDir).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)));
                    try { Environment.SetEnvironmentVariable("PATH", updatedPath, EnvironmentVariableTarget.User); Theme.LogOk("removed from PATH"); }
                    catch (Exception ex) { Theme.Error($"failed: {ex.Message}"); }
                    break;

                default:
                    Theme.Error("unknown subcommand  (status · enable · disable)");
                    break;
            }
        }

        private static void ToggleMode()
        {
            _currentMode = _currentMode switch { AppMode.Chat => AppMode.Agent, _ => AppMode.Chat };
            var desc = _currentMode switch
            {
                AppMode.Agent => "agent — tools enabled",
                _             => "chat — plain conversation"
            };
            Theme.LogOk(desc);
            _statusBarNeedsUpdate = true;
        }

        private static void ShowTools()
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"  [{Theme.Muted}]tools[/]");
            UIService.Divider("grey19");
            foreach (var t in GetToolDefinitions())
            {
                var cat   = _permissionManager!.GetToolCategory(t.Name);
                var color = Theme.CategoryColor(cat);
                AnsiConsole.MarkupLine($"  [{color}]{t.Name,-20}[/][{Theme.Muted}]{t.Description}[/]");
            }
            AnsiConsole.WriteLine();
        }

        private static void ShowPermissions()
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"  [{Theme.Muted}]permissions[/]  [{Theme.Dim}]cwd: {_permissionManager!.GetCurrentWorkingDirectory()}[/]");
            UIService.Divider("grey19");

            var tools = new[] { "execute_shell","write_file","delete_file","read_file","list_directory","search_file","analyze_code","check_path","get_env","calculate","search_web","system_info","analyze_image" };
            foreach (var tool in tools)
            {
                var cat      = _permissionManager!.GetToolCategory(tool);
                var session  = _permissionManager.IsAllowedForSession(tool);
                var permStr  = session ? $"[{Theme.Ok}]session[/]" : _permissionManager.GetPermission(tool) switch
                {
                    Permission.AllowAlways => $"[{Theme.Ok}]always[/]",
                    Permission.Deny        => $"[{Theme.Err}]deny[/]",
                    _                      => $"[{Theme.Muted}]ask[/]"
                };
                AnsiConsole.MarkupLine($"  [{Theme.CategoryColor(cat)}]{tool,-20}[/][{Theme.Dim}]{cat,-14}[/]{permStr}");
            }
            AnsiConsole.WriteLine();
            Theme.Hint("/perms reset   /perms clear-session");
        }

        private static async Task SendMessageAsync(string userMessage)
        {
            if (_isGenerating) { Theme.LogWarn("already generating — Ctrl+C to cancel"); return; }

            _cts?.Dispose();
            _cts = new CancellationTokenSource();

            if (!string.IsNullOrEmpty(_pendingImageBase64) && string.IsNullOrEmpty(userMessage))
                userMessage = "Describe this image in detail.";

            var msg = new Message { Role = MessageRole.User, Content = userMessage, Timestamp = DateTime.Now };
            if (!string.IsNullOrEmpty(_pendingImageBase64)) { msg.ImageBase64 = _pendingImageBase64; _pendingImageBase64 = null; }
            _messages.Add(msg);

            _ui!.ShowUserMessage(userMessage, _userName);

            if      (_currentProvider == ApiProvider.Mistral && _currentMode != AppMode.Agent) await RunMistralChatAsync(_cts.Token);
            else if (_currentProvider == ApiProvider.Mistral) await RunMistralAgentAsync(_cts.Token);
            else if (_currentMode == AppMode.Chat)            await RunChatAsync(_cts.Token);
            else                                              await RunAgentAsync(userMessage, _cts.Token);
        }

        private static string StripMarkdown(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            text = Regex.Replace(text, @"(\*\*|__)(.+?)\1", "$2");
            text = Regex.Replace(text, @"(\*|_)(.+?)\1", "$2");
            text = Regex.Replace(text, @"`(.+?)`", "$1");
            text = Regex.Replace(text, @"```[\s\S]*?```", "");
            text = Regex.Replace(text, @"^#{1,6}\s+(.+)$", "$1", RegexOptions.Multiline);
            text = Regex.Replace(text, @"~~(.+?)~~", "$1");
            text = Regex.Replace(text, @"\[([^\]]+)\]\([^)]+\)", "$1");
            text = Regex.Replace(text, @"!\[([^\]]*)\]\([^)]+\)", "$1");
            return text;
        }

        private static string FilterJsonBlocks(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            text = Regex.Replace(text, @"```json\s*\{[^}]*\}\s*```", "", RegexOptions.Singleline);
            text = Regex.Replace(text, @"```json\s*", "");
            text = Regex.Replace(text, @"\s*```", "");
            return text.Trim();
        }

        private static async Task RunMistralChatAsync(CancellationToken cancellationToken)
        {
            if (_mistralService == null) { Theme.Error("Mistral not configured — use /api"); return; }

            _isGenerating = true;
            var fullResponse = new StringBuilder();

            try
            {
                _ui!.BeginAiMessage();
                await foreach (var chunk in _mistralService.ChatStreamAsync(_selectedModel, _messages.TakeLast(20).ToList(), null, 0.7, cancellationToken))
                {
                    var content = chunk.Choices?.FirstOrDefault()?.Delta?.Content;
                    if (content != null)
                    {
                        fullResponse.Append(content);
                        Console.Write(Theme.Esc(StripMarkdown(content)));
                        Console.Out.Flush();
                    }
                }
                Console.WriteLine();
                var final = fullResponse.ToString().Trim();
                if (!string.IsNullOrWhiteSpace(final))
                    _messages.Add(new Message { Role = MessageRole.Assistant, Content = StripMarkdown(final), Model = _selectedModel });
                Console.WriteLine();
            }
            catch (OperationCanceledException) { AnsiConsole.MarkupLine($"\n  [{Theme.Warn}]cancelled[/]"); }
            catch (Exception ex)               { AnsiConsole.MarkupLine($"\n  [{Theme.Err}]{Theme.Esc(ex.Message)}[/]"); }
            finally { _isGenerating = false; }
        }

        private static async Task RunMistralAgentAsync(CancellationToken cancellationToken)
        {
            if (_mistralService == null) { Theme.Error("Mistral not configured — use /api"); return; }

            _isGenerating = true;
            var tools        = GetToolDefinitions();
            var conversation = new List<Message> { new() { Role = MessageRole.System, Content = GenerateSystemPrompt() } };
            conversation.AddRange(_messages.TakeLast(10));

            _ui!.ShowThinking();

            try
            {
                for (int iteration = 0; iteration < 10; iteration++)
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    var responseContent   = new StringBuilder();
                    List<ToolCall>? toolCalls = null;
                    bool gotToolCalls    = false;
                    bool startedStreaming = false;

                    await foreach (var chunk in _mistralService.ChatStreamAsync(_selectedModel, conversation, tools, 0.7, cancellationToken))
                    {
                        var content = chunk.Choices?.FirstOrDefault()?.Delta?.Content;
                        if (content != null)
                        {
                            responseContent.Append(content);
                            
                            if (!startedStreaming)
                            {
                                startedStreaming = true;
                                Console.WriteLine();
                                _ui!.BeginAiMessage();
                            }
                            Console.Write(Theme.Esc(StripMarkdown(content)));
                            Console.Out.Flush();
                        }

                        if (chunk.Choices?.FirstOrDefault()?.Delta?.ToolCalls != null)
                        {
                            var tc = chunk.Choices.FirstOrDefault()?.Delta?.ToolCalls;
                            if (tc != null && tc.Any())
                            {
                                // Preserve original tool call IDs from the AI response
                                if (toolCalls == null)
                                    toolCalls = new List<ToolCall>();
                                
                                foreach (var t in tc)
                                {
                                    var existingCall = toolCalls.FirstOrDefault(existing => existing.Id == t.Id);
                                    if (existingCall != null)
                                    {
                                        // Update existing tool call with new data
                                        if (!string.IsNullOrEmpty(t.Function?.Name))
                                            existingCall.Function.Name = t.Function.Name;
                                        if (!string.IsNullOrEmpty(t.Function?.ArgumentsString))
                                            existingCall.Function.Arguments = JsonSerializer.Deserialize<Dictionary<string, object>>(t.Function.ArgumentsString) ?? new Dictionary<string, object>();
                                    }
                                    else
                                    {
                                        // Add new tool call, preserving the original ID
                                        toolCalls.Add(new ToolCall
                                        {
                                            Id = t.Id ?? Guid.NewGuid().ToString()[..8],
                                            Function = new ToolFunction 
                                            {
                                                Name = t.Function?.Name ?? "",
                                                Arguments = string.IsNullOrEmpty(t.Function?.ArgumentsString) ? 
                                                    new Dictionary<string, object>() :
                                                    JsonSerializer.Deserialize<Dictionary<string, object>>(t.Function.ArgumentsString) ?? new Dictionary<string, object>()
                                            }
                                        });
                                    }
                                }
                                gotToolCalls = true;
                                // Continue streaming to get complete tool call data
                            }
                        }
                    }

                    if (startedStreaming) Console.WriteLine();

                    var rawResponse = responseContent.ToString();
                    if (!gotToolCalls && !string.IsNullOrWhiteSpace(rawResponse))
                        toolCalls = ExtractToolCallsFromText(rawResponse);

                    var hasToolCalls = gotToolCalls || (toolCalls != null && toolCalls.Any());
                    
                    // Always add to conversation - either with content OR tool_calls, never both empty
                    if (hasToolCalls)
                    {
                        conversation.Add(new Message { Role = MessageRole.Assistant, Content = null, ToolCalls = toolCalls, Model = _selectedModel });
                    }
                    else if (!string.IsNullOrWhiteSpace(rawResponse))
                    {
                        conversation.Add(new Message { Role = MessageRole.Assistant, Content = rawResponse, ToolCalls = null, Model = _selectedModel });
                    }
                    else
                    {
                        // Empty response with no tool calls - skip adding
                        break;
                    }

                    if (!hasToolCalls)
                    {
                        var displayResponse = StripMarkdown(FilterJsonBlocks(rawResponse)).Trim();
                        if (!startedStreaming && !string.IsNullOrWhiteSpace(displayResponse))
                        {
                            Console.WriteLine();
                            _ui!.ShowAiMessage(displayResponse);
                            _messages.Add(new Message { Role = MessageRole.Assistant, Content = displayResponse, Model = _selectedModel });
                        }
                        else if (startedStreaming)
                        {
                            _messages.Add(new Message { Role = MessageRole.Assistant, Content = StripMarkdown(rawResponse.Trim()), Model = _selectedModel });
                        }
                        break;
                    }

                    Console.WriteLine();
                    foreach (var tc in toolCalls)
                    {
                        _ui!.ShowToolStart(tc.Function.Name);
                        var result = await HandleToolPermissionAsync(tc);

                        if (tc.Function.Name == "search_web" && result.ContainsKey("browser_fallback_available") && result.ContainsKey("error"))
                            result = await _toolKit!.AskForBrowserFallbackAsync(GetArg(tc.Function.Arguments, "query"));

                        conversation.Add(new Message { Role = MessageRole.Tool, ToolName = tc.Id, Content = JsonSerializer.Serialize(result) });

                        var summary = GetToolResultSummary(tc.Function.Name, result);
                        _ui!.ShowToolResult(tc.Function.Name, !result.ContainsKey("error"), summary);
                    }
                }
            }
            catch (OperationCanceledException) { AnsiConsole.MarkupLine($"\n  [{Theme.Warn}]cancelled[/]"); }
            catch (Exception ex)               { AnsiConsole.MarkupLine($"\n  [{Theme.Err}]{Theme.Esc(ex.Message)}[/]"); }
            finally { _isGenerating = false; }
        }

        private static async Task RunChatAsync(CancellationToken cancellationToken)
        {
            _isGenerating = true;
            var fullResponse = new StringBuilder();

            try
            {
                _ui!.BeginAiMessage();
                await foreach (var chunk in _apiService!.ChatStreamAsync(_selectedModel, _messages.TakeLast(20).ToList(), null, 0.7, cancellationToken))
                {
                    var content = chunk.Message?.Content;
                    if (content != null)
                    {
                        fullResponse.Append(content);
                        Console.Write(Theme.Esc(StripMarkdown(content)));
                        Console.Out.Flush();
                    }
                }
                Console.WriteLine();
                var final = fullResponse.ToString().Trim();
                if (!string.IsNullOrWhiteSpace(final))
                    _messages.Add(new Message { Role = MessageRole.Assistant, Content = StripMarkdown(final), Model = _selectedModel });
                Console.WriteLine();
            }
            catch (OperationCanceledException) { AnsiConsole.MarkupLine($"\n  [{Theme.Warn}]cancelled[/]"); }
            catch (Exception ex)               { AnsiConsole.MarkupLine($"\n  [{Theme.Err}]{Theme.Esc(ex.Message)}[/]"); }
            finally { _isGenerating = false; }
        }

        private static async Task RunAgentAsync(string userMessage, CancellationToken cancellationToken)
        {
            _isGenerating = true;
            var tools        = GetToolDefinitions();
            var conversation = new List<Message> { new() { Role = MessageRole.System, Content = GenerateSystemPrompt() } };
            conversation.AddRange(_messages.TakeLast(10));

            _ui!.ShowThinking();

            bool toolsTried = false;

            try
            {
                for (int iteration = 0; iteration < 10; iteration++)
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    var responseContent   = new StringBuilder();
                    List<ToolCall>? toolCalls = null;
                    bool gotToolCalls    = false;
                    bool startedStreaming = false;
                    bool toolsSupported  = true;

                    try
                    {
                        await foreach (var chunk in _apiService!.ChatStreamAsync(_selectedModel, conversation, tools, 0.7, cancellationToken))
                        {
                            if (chunk.Message?.Content != null)
                            {
                                var content = chunk.Message.Content;
                                responseContent.Append(content);

                                var currentText    = responseContent.ToString().Trim();
                                bool looksLikeJson = currentText.StartsWith("{") && currentText.Contains("tool");

                                if (!looksLikeJson && !gotToolCalls)
                                {
                                    if (!startedStreaming)
                                    {
                                        startedStreaming = true;
                                        Console.WriteLine();
                                        _ui!.BeginAiMessage();
                                    }
                                    Console.Write(Theme.Esc(StripMarkdown(content)));
                                    Console.Out.Flush();
                                }
                            }

                            if (chunk.Message?.ToolCalls != null && chunk.Message.ToolCalls.Any())
                            {
                                toolCalls    = chunk.Message.ToolCalls;
                                gotToolCalls = true;
                            }
                        }
                    }
                    catch (HttpRequestException ex) when (ex.Message.Contains("does not support tools"))
                    {
                        toolsSupported = false;
                        if (!toolsTried)
                        {
                            toolsTried = true;
                            Console.WriteLine();
                            Theme.LogWarn("model doesn't support tools — retrying without");
                            conversation = new List<Message> { new() { Role = MessageRole.System, Content = GenerateSystemPromptNoTools() } };
                            conversation.AddRange(_messages.TakeLast(10));
                            continue;
                        }
                        else throw;
                    }

                    if (startedStreaming) Console.WriteLine();

                    var rawResponse = responseContent.ToString();
                    if (!gotToolCalls && !string.IsNullOrWhiteSpace(rawResponse))
                        toolCalls = ExtractToolCallsFromText(rawResponse);

                    var hasToolCalls = gotToolCalls || (toolCalls != null && toolCalls.Any());

                    if (hasToolCalls)
                    {
                        conversation.Add(new Message { Role = MessageRole.Assistant, Content = null, ToolCalls = toolCalls, Model = _selectedModel });
                    }
                    else if (!string.IsNullOrWhiteSpace(rawResponse))
                    {
                        conversation.Add(new Message { Role = MessageRole.Assistant, Content = rawResponse, ToolCalls = null, Model = _selectedModel });
                    }
                    else
                    {
                        break;
                    }

                    if (!hasToolCalls && toolsSupported)
                    {
                        var displayResponse = StripMarkdown(FilterJsonBlocks(rawResponse)).Trim();
                        if (!startedStreaming && !string.IsNullOrWhiteSpace(displayResponse))
                        {
                            Console.WriteLine();
                            _ui!.ShowAiMessage(displayResponse);
                            _messages.Add(new Message { Role = MessageRole.Assistant, Content = displayResponse, Model = _selectedModel });
                        }
                        else if (startedStreaming)
                        {
                            _messages.Add(new Message { Role = MessageRole.Assistant, Content = StripMarkdown(rawResponse.Trim()), Model = _selectedModel });
                        }
                        break;
                    }

                    Console.WriteLine();
                    foreach (var tc in toolCalls)
                    {
                        _ui!.ShowToolStart(tc.Function.Name);
                        var result = await HandleToolPermissionAsync(tc);

                        if (tc.Function.Name == "search_web" && result.ContainsKey("browser_fallback_available") && result.ContainsKey("error"))
                            result = await _toolKit!.AskForBrowserFallbackAsync(GetArg(tc.Function.Arguments, "query"));

                        conversation.Add(new Message { Role = MessageRole.Tool, ToolName = tc.Function.Name, Content = JsonSerializer.Serialize(result) });

                        var summary = GetToolResultSummary(tc.Function.Name, result);
                        _ui!.ShowToolResult(tc.Function.Name, !result.ContainsKey("error"), summary);
                    }
                }
            }
            catch (OperationCanceledException) { AnsiConsole.MarkupLine($"\n  [{Theme.Warn}]cancelled[/]"); }
            catch (Exception ex)               { AnsiConsole.MarkupLine($"\n  [{Theme.Err}]{Theme.Esc(ex.Message)}[/]"); }
            finally { _isGenerating = false; }
        }


        private static string[] GetRequiredParams(string toolName) => toolName switch
        {
            "read_file"     => new[] { "path" },
            "write_file"    => new[] { "path", "content" },
            "list_directory"=> new[] { "path" },
            "execute_shell" => new[] { "command" },
            "search_file"   => new[] { "path", "search_term" },
            "analyze_code"  => new[] { "path" },
            "analyze_image" => new[] { "path" },
            "calculate"     => new[] { "expression" },
            "search_web"    => new[] { "query" },
            "check_path"    => new[] { "path" },
            "get_env"       => new[] { "varName" },
            _               => Array.Empty<string>()
        };

        private static string? DetectToolFromKeywords(string message)
        {
            var msg = message.ToLower();
            if (msg.Contains("search") || msg.Contains("google") || msg.Contains("web"))   return "search_web";
            if (msg.Contains("read")   || msg.Contains("contents of"))                      return "read_file";
            if (msg.Contains("write")  || msg.Contains("save")  || msg.Contains("create file")) return "write_file";
            if (msg.Contains("list")   || msg.Contains("directory") || msg.Contains("ls")) return "list_directory";
            if (msg.Contains("calculate") || msg.Contains("compute") || msg.Contains("math")) return "calculate";
            if (msg.Contains("run")    || msg.Contains("execute") || msg.Contains("shell")) return "execute_shell";
            if (msg.Contains("image")  || msg.Contains("picture") || msg.Contains("photo")) return "analyze_image";
            if (msg.Contains("analyze code") || msg.Contains("lines of code"))              return "analyze_code";
            if (msg.Contains("search in") || msg.Contains("grep") || msg.Contains("find text")) return "search_file";
            if (msg.Contains("system") || msg.Contains("sysinfo"))                          return "system_info";
            return null;
        }

        private static List<ToolCall>? ExtractToolCallsFromText(string text)
        {
            var calls = new List<ToolCall>();
            if (string.IsNullOrWhiteSpace(text)) return null;

            // Try direct JSON object
            try
            {
                var trimmed = text.Trim();
                if (trimmed.StartsWith("{") && trimmed.EndsWith("}"))
                {
                    using var doc = JsonDocument.Parse(trimmed);
                    if (doc.RootElement.TryGetProperty("function", out var fe) && fe.TryGetProperty("name", out var ne))
                    {
                        var toolName = ne.GetString();
                        var args = new Dictionary<string, object>();
                        if (fe.TryGetProperty("arguments", out var ae))
                        {
                            if (ae.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(ae.GetString()))
                                try { args = JsonSerializer.Deserialize<Dictionary<string, object>>(ae.GetString()!) ?? new(); } catch { }
                            else if (ae.ValueKind == JsonValueKind.Object)
                                foreach (var p in ae.EnumerateObject()) args[p.Name] = p.Value.ToString();
                        }
                        if (!string.IsNullOrEmpty(toolName) && args.Any())
                            return new List<ToolCall> { new() { Function = new() { Name = toolName, Arguments = args } } };
                    }
                }
            }
            catch { }

            // Pattern match
            try
            {
                var pattern = @"\{\s*""tool""\s*:\s*""([^""]+)""\s*,\s*""params""\s*:\s*(\{[^}]+\})\s*\}";
                foreach (Match m in Regex.Matches(text, pattern, RegexOptions.Singleline))
                {
                    var args = JsonSerializer.Deserialize<Dictionary<string, object>>(m.Groups[2].Value) ?? new();
                    calls.Add(new() { Function = new() { Name = m.Groups[1].Value, Arguments = args } });
                }
            }
            catch { }

            return calls.Any() ? calls : null;
        }

        private static async Task<Dictionary<string, object>> ExecuteToolAsync(ToolCall toolCall)
        {
            var name = toolCall.Function.Name;
            var args = toolCall.Function.Arguments;
            return name switch
            {
                "read_file"      => _toolKit!.ReadFile(GetArg(args, "path")),
                "write_file"     => _toolKit!.WriteFile(GetArg(args, "path"), GetArg(args, "content")),
                "list_directory" => _toolKit!.ListDirectory(GetArg(args, "path", ".")),
                "execute_shell"  => await _toolKit!.ExecuteShell(GetArg(args, "command")),
                "system_info"    => _toolKit!.SystemInfo(),
                "search_file"    => _toolKit!.SearchFile(GetArg(args, "path"), GetArg(args, "search_term")),
                "analyze_code"   => _toolKit!.AnalyzeCode(GetArg(args, "path")),
                "analyze_image"  => _toolKit!.AnalyzeImage(GetArg(args, "path")),
                "check_path"     => _toolKit!.CheckPath(GetArg(args, "path")),
                "get_env"        => _toolKit!.GetEnv(GetArg(args, "var_name", "")),
                "calculate"      => _toolKit!.Calculate(GetArg(args, "expression")),
                "search_web"     => await _toolKit!.SearchWebAsync(GetArg(args, "query")),
                _                => new Dictionary<string, object> { ["error"] = $"Unknown tool: {name}" }
            };
        }

        private static string GetArg(Dictionary<string, object> args, string key, string defaultValue = "") =>
            args.TryGetValue(key, out var value) ? value?.ToString() ?? defaultValue : defaultValue;

        private static async Task<Dictionary<string, object>> HandleToolPermissionAsync(ToolCall toolCall)
        {
            var toolName = toolCall.Function.Name;
            var args     = toolCall.Function.Arguments;

            if (_permissionManager!.IsAllowedForSession(toolName)) return await ExecuteToolAsync(toolCall);
            var permission = _permissionManager.GetPermission(toolName);
            if (permission == Permission.Deny)       return new Dictionary<string, object> { ["error"] = $"Permission denied: {toolName}" };
            if (permission == Permission.AllowAlways) return await ExecuteToolAsync(toolCall);

            var category = _permissionManager.GetToolCategory(toolName);
            var isDangerous = _permissionManager.IsDangerousTool(toolName);

            Console.WriteLine($"[DEBUG] Permission check: {toolName}, category={category}, dangerous={isDangerous}, permission={_permissionManager.GetPermission(toolName)}");

            string? targetPath = null;
            bool isOutsideCwd  = false;
            if (toolName is "read_file" or "write_file" or "list_directory" or "search_file" or "analyze_code" or "check_path" or "analyze_image" && args.TryGetValue("path", out var pathObj))
            {
                targetPath    = pathObj?.ToString() ?? "";
                isOutsideCwd  = _permissionManager.IsPathOutsideCwd(targetPath);
            }

            string? cmd = null;
            if (toolName == "execute_shell" && args.TryGetValue("command", out var cmdObj))
                cmd = cmdObj?.ToString();

            var input = _ui!.PromptPermission(toolName, category, isDangerous, isOutsideCwd, targetPath, cmd, _permissionManager.GetCurrentWorkingDirectory());

            if (input == "a")
            {
                return await ExecuteToolAsync(toolCall);
            }
            if (input == "s")
            {
                _permissionManager!.AllowForSession(toolName);
                return await ExecuteToolAsync(toolCall);
            }
            if (input == "d" || input == "n")
            {
                _permissionManager!.SetPermission(toolName, Permission.Deny);
                return new Dictionary<string, object> { ["error"] = $"Permission denied: {toolName}" };
            }
            return new Dictionary<string, object> { ["error"] = "Permission request cancelled" };
        }

        private static List<ToolDefinition> GetToolDefinitions() => new()
        {
            new() { Name = "read_file",      Description = "Read file contents",                Parameters = new { type = "object", properties = new { path    = new { type = "string", description = "File path" } },                                             required = new[] { "path" } } },
            new() { Name = "write_file",     Description = "Write content to a file",           Parameters = new { type = "object", properties = new { path    = new { type = "string", description = "File path" }, content = new { type = "string", description = "Content" } }, required = new[] { "path", "content" } } },
            new() { Name = "list_directory", Description = "List files and directories",        Parameters = new { type = "object", properties = new { path    = new { type = "string", description = "Directory path" } } } },
            new() { Name = "execute_shell",  Description = "Execute shell command",             Parameters = new { type = "object", properties = new { command = new { type = "string", description = "Command" } },                                               required = new[] { "command" } } },
            new() { Name = "search_file",    Description = "Search for text in file",          Parameters = new { type = "object", properties = new { path    = new { type = "string", description = "File path" }, search_term = new { type = "string", description = "Text to search" } }, required = new[] { "path", "search_term" } } },
            new() { Name = "analyze_code",   Description = "Code file statistics",             Parameters = new { type = "object", properties = new { path    = new { type = "string", description = "File path" } },                                             required = new[] { "path" } } },
            new() { Name = "analyze_image",  Description = "Vision analysis of an image file", Parameters = new { type = "object", properties = new { path    = new { type = "string", description = "Image path" } },                                            required = new[] { "path" } } },
            new() { Name = "calculate",      Description = "Math expression evaluation",       Parameters = new { type = "object", properties = new { expression = new { type = "string", description = "Expression" } },                                         required = new[] { "expression" } } },
            new() { Name = "search_web",     Description = "Web search (multi-engine)",        Parameters = new { type = "object", properties = new { query   = new { type = "string", description = "Search query" } },                                          required = new[] { "query" } } },
        };

        private static string GetToolResultSummary(string toolName, Dictionary<string, object> result)
        {
            try
            {
                object? V(string key) => result.TryGetValue(key, out var v) ? v : null;
                return toolName switch
                {
                    "list_directory" => $"{V("total") ?? 0} items  in  {V("path") ?? ""}",
                    "read_file"      => $"{V("size") ?? 0} bytes{(result.ContainsKey("truncated") ? " (truncated)" : "")}",
                    "write_file"     => $"wrote {V("bytes_written") ?? 0} bytes",
                    "execute_shell"  => (V("success") as bool?) == true ? "exit 0" : $"exit {V("exit_code") ?? -1}",
                    "search_file"    => $"{V("matches") ?? 0} matches",
                    "analyze_code"   => $"{V("total_lines") ?? 0} lines",
                    "analyze_image"  => $"{V("filename") ?? ""}  {V("width") ?? 0}×{V("height") ?? 0}",
                    "check_path"     => (V("exists") as bool?) == true ? "exists" : "not found",
                    "calculate"      => $"= {V("result") ?? ""}",
                    "search_web"     => $"{V("count") ?? 0} results",
                    "system_info"    => $"{V("platform") ?? ""}",
                    "get_env"        => "retrieved",
                    _                => ""
                };
            }
            catch { return ""; }
        }

        private static string GenerateSystemPrompt() =>
            $@"You are a helpful AI assistant.

Current directory: {Environment.CurrentDirectory}
Platform: {RuntimeInformation.OSDescription}

When using a tool, respond ONLY with this JSON:
{{""tool"": ""tool_name"", ""params"": {{""key"": ""value""}}}}

Wait for the tool result before continuing. Keep responses concise and plain — no markdown.";

        private static string GenerateSystemPromptNoTools() =>
            $@"You are a helpful AI assistant.
Current directory: {Environment.CurrentDirectory}
Platform: {RuntimeInformation.OSDescription}
NOTE: This model does not support tools. Respond in plain text only, concisely.";
    }
}