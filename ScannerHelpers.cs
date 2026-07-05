using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using System.Text.RegularExpressions;

namespace GamerIntegrity
{
    public static class ScannerHelpers
    {
        public const string ReleaseVersion = "v1.0.1";
        public const string EvidenceModelVersion = "evidence-v1.0.1";

        public static int Clamp(int value, int low, int high)
        {
            return Math.Max(low, Math.Min(high, value));
        }

        public static string SeverityToString(Severity severity)
        {
            return severity.ToString();
        }

        public static string ToLowerSafe(string value)
        {
            return (value ?? "").ToLowerInvariant();
        }

        public static bool ContainsInsensitive(string value, string token)
        {
            if (string.IsNullOrEmpty(value) || string.IsNullOrEmpty(token)) return false;
            return value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool StartsWithInsensitive(string value, string prefix)
        {
            return (value ?? "").StartsWith(prefix ?? "", StringComparison.OrdinalIgnoreCase);
        }

        public static bool EndsWithInsensitive(string value, string suffix)
        {
            return (value ?? "").EndsWith(suffix ?? "", StringComparison.OrdinalIgnoreCase);
        }

        public static string Trim(string value)
        {
            return (value ?? "").Trim(' ', '\t', '\r', '\n', '"');
        }

        public static string NormalizeNameForMatch(string input)
        {
            var sb = new StringBuilder();
            bool lastSpace = false;
            foreach (char ch in ToLowerSafe(input))
            {
                if (char.IsLetterOrDigit(ch))
                {
                    sb.Append(ch);
                    lastSpace = false;
                }
                else if (!lastSpace)
                {
                    sb.Append(' ');
                    lastSpace = true;
                }
            }
            return Trim(sb.ToString());
        }

        public static bool RuleMatchesName(string value, string token)
        {
            string normName = " " + NormalizeNameForMatch(value) + " ";
            string normToken = NormalizeNameForMatch(token);
            if (normToken.Length == 0) return false;
            if (normName.Contains(" " + normToken + " ")) return true;

            string collapsedName = Regex.Replace(normName, "\\s+", "");
            string collapsedToken = Regex.Replace(normToken, "\\s+", "");
            return collapsedToken.Length >= 8 && collapsedName.Contains(collapsedToken);
        }

        public static bool RuleMatchesLoose(string value, string token)
        {
            if (RuleMatchesName(value, token)) return true;
            string lowerValue = ToLowerSafe(value);
            string lowerToken = ToLowerSafe(token);
            if (lowerToken.Length >= 6 && lowerValue.Contains(lowerToken)) return true;
            string compactValue = Regex.Replace(lowerValue, "[^a-z0-9]+", "");
            string compactToken = Regex.Replace(lowerToken, "[^a-z0-9]+", "");
            return compactToken.Length >= 8 && compactValue.Contains(compactToken);
        }

        public static string CollapseWhitespaceForDisplay(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return "";
            return Regex.Replace(input, "\\s+", " ").Trim();
        }

        public static string JsonEscape(string value)
        {
            if (value == null) return "";
            var sb = new StringBuilder(value.Length + 16);
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        public static string HtmlEscape(string value)
        {
            if (value == null) return "";
            return value.Replace("&", "&amp;")
                        .Replace("<", "&lt;")
                        .Replace(">", "&gt;")
                        .Replace("\"", "&quot;")
                        .Replace("'", "&#39;");
        }

        public static string CurrentLocalTimestamp()
        {
            return DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        }

        public static string CurrentLocalDisplayTimestamp()
        {
            return DateTime.Now.ToString("M/d/yyyy h:mm tt", CultureInfo.InvariantCulture);
        }

        public static string FriendlyTimestampText(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return Regex.Replace(value, "\\b(\\d{4})-(\\d{2})-(\\d{2}) (\\d{2}):(\\d{2}):(\\d{2})\\b", m =>
            {
                DateTime dt;
                if (DateTime.TryParseExact(m.Value, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out dt))
                    return dt.ToString("M/d/yyyy h:mm tt", CultureInfo.InvariantCulture);
                return m.Value;
            });
        }

        public static string FileTimeString(string path)
        {
            try
            {
                if (!File.Exists(path)) return "";
                return File.GetLastWriteTime(path).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            }
            catch { return ""; }
        }

        public static string EntryLastWriteTimeString(string path)
        {
            try
            {
                if (File.Exists(path)) return File.GetLastWriteTime(path).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
                if (Directory.Exists(path)) return Directory.GetLastWriteTime(path).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            }
            catch { }
            return "";
        }

        public static string GetWindowsDirectoryPath()
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        }

        public static string GetSystemDrivePath()
        {
            return Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        }

        public static string NormalizeKernelModulePath(string rawPath)
        {
            string path = Trim(rawPath);
            if (path.Length == 0) return path;

            string windowsDir = GetWindowsDirectoryPath();
            string systemDrive = GetSystemDrivePath();
            if (StartsWithInsensitive(path, @"\??\")) path = path.Substring(4);
            else if (StartsWithInsensitive(path, @"\SystemRoot\")) path = windowsDir + path.Substring(@"\SystemRoot".Length);
            else if (StartsWithInsensitive(path, @"SystemRoot\")) path = Path.Combine(windowsDir, path.Substring(@"SystemRoot\".Length));
            else if (StartsWithInsensitive(path, @"\Windows\")) path = systemDrive + path;
            else if (StartsWithInsensitive(path, @"Windows\")) path = Path.Combine(systemDrive + @"\", path);
            else if (StartsWithInsensitive(path, @"\System32\")) path = windowsDir + path;
            else if (StartsWithInsensitive(path, @"System32\")) path = Path.Combine(windowsDir, path);

            return Environment.ExpandEnvironmentVariables(path);
        }

        public static string NormalizeServiceBinaryPath(string raw)
        {
            string path = Trim(raw);
            if (path.Length == 0) return path;

            if (path[0] == '"')
            {
                int second = path.IndexOf('"', 1);
                if (second > 0) path = path.Substring(1, second - 1);
            }
            else
            {
                string lower = ToLowerSafe(path);
                int cut = -1;
                foreach (string ext in new[] { ".sys", ".exe", ".dll" })
                {
                    int pos = lower.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
                    if (pos >= 0)
                    {
                        cut = pos + ext.Length;
                        break;
                    }
                }
                if (cut < 0)
                {
                    int space = path.IndexOf(' ');
                    if (space >= 0) cut = space;
                }
                if (cut >= 0) path = path.Substring(0, cut);
            }
            return NormalizeKernelModulePath(path);
        }

        public static bool IsWindowsSystemPath(string path)
        {
            string lower = ToLowerSafe(NormalizeKernelModulePath(path));
            string win = ToLowerSafe(GetWindowsDirectoryPath().TrimEnd('\\') + "\\");
            return lower.StartsWith(win, StringComparison.OrdinalIgnoreCase);
        }

        public static string GetFileNameOnly(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return "";
            try { return Path.GetFileName(path); } catch { return path; }
        }

        public static string Sha256File(string path)
        {
            try
            {
                if (!File.Exists(path)) return "";
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var sha = SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch { return ""; }
        }

        public static string FileCompanyName(string path)
        {
            try
            {
                if (!File.Exists(path)) return "";
                return FileVersionInfo.GetVersionInfo(path).CompanyName ?? "";
            }
            catch { return ""; }
        }

        public static bool HasAuthenticodeSignature(string path)
        {
            return IsFileSignatureTrusted(path);
        }

        public static bool IsFileSignatureTrusted(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return false;
            if (!OperatingSystem.IsWindows()) return false;

            Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                pcwszFilePath = path,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            IntPtr fileInfoPtr = IntPtr.Zero;
            IntPtr dataPtr = IntPtr.Zero;
            try
            {
                fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                WINTRUST_DATA data = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pFile = fileInfoPtr,
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = null,
                    dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL,
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero
                };

                dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA)));
                Marshal.StructureToPtr(data, dataPtr, false);
                uint result = WinVerifyTrust(IntPtr.Zero, action, dataPtr);

                data = (WINTRUST_DATA)Marshal.PtrToStructure(dataPtr, typeof(WINTRUST_DATA));
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                Marshal.StructureToPtr(data, dataPtr, false);
                WinVerifyTrust(IntPtr.Zero, action, dataPtr);

                return result == 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (dataPtr != IntPtr.Zero) Marshal.FreeHGlobal(dataPtr);
                if (fileInfoPtr != IntPtr.Zero) Marshal.FreeHGlobal(fileInfoPtr);
            }
        }

        public static string GenerateReportId()
        {
            var bytes = new byte[4];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
            return "GI-" + DateTime.Now.ToString("yyyy_MM_dd_HH_mm_ss", CultureInfo.InvariantCulture) + "-" + BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        public static string SafeComputerName()
        {
            try { return Environment.MachineName; } catch { return "Unknown"; }
        }

        public static string SafeUserName()
        {
            try { return Environment.UserName; } catch { return "Unknown"; }
        }

        public static List<Dictionary<string, string>> WmiQueryRows(string nameSpace, string query, params string[] fields)
        {
            var rows = new List<Dictionary<string, string>>();
            try
            {
                using (var searcher = new ManagementObjectSearcher(nameSpace, query))
                using (var results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        using (obj)
                        {
                            var row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                            foreach (string field in fields)
                            {
                                try { row[field] = Convert.ToString(obj[field], CultureInfo.InvariantCulture) ?? ""; }
                                catch { row[field] = ""; }
                            }
                            rows.Add(row);
                        }
                    }
                }
            }
            catch { }
            return rows;
        }

        public static string WmiValue(Dictionary<string, string> row, string key)
        {
            string value;
            return row != null && row.TryGetValue(key, out value) ? Trim(value) : "";
        }

        public static string ReadRegistryString(RegistryHive hive, string subkey, string name, RegistryView view = RegistryView.Registry64)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(hive, view))
                using (var key = baseKey.OpenSubKey(subkey))
                {
                    object value = key?.GetValue(name);
                    return Trim(value == null ? "" : value.ToString());
                }
            }
            catch { return ""; }
        }

        public static int? ReadRegistryDword(RegistryHive hive, string subkey, string name, RegistryView view = RegistryView.Registry64)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(hive, view))
                using (var key = baseKey.OpenSubKey(subkey))
                {
                    object value = key?.GetValue(name);
                    if (value is int i) return i;
                    if (value is long l) return (int)l;
                    int parsed;
                    if (value != null && int.TryParse(value.ToString(), out parsed)) return parsed;
                }
            }
            catch { }
            return null;
        }

        public static IEnumerable<string> EnumerateSubKeyNames(RegistryHive hive, string subkey, RegistryView view = RegistryView.Registry64)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(hive, view))
                using (var key = baseKey.OpenSubKey(subkey))
                {
                    return key?.GetSubKeyNames() ?? new string[0];
                }
            }
            catch { return new string[0]; }
        }

        public static Dictionary<string, object> ReadRegistryValues(RegistryHive hive, string subkey, RegistryView view = RegistryView.Registry64)
        {
            var values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(hive, view))
                using (var key = baseKey.OpenSubKey(subkey))
                {
                    if (key == null) return values;
                    foreach (string name in key.GetValueNames()) values[name] = key.GetValue(name);
                }
            }
            catch { }
            return values;
        }

        public static object ReadRegistryValue(RegistryHive hive, string subkey, string name, RegistryView view = RegistryView.Registry64)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(hive, view))
                using (var key = baseKey.OpenSubKey(subkey))
                {
                    return key == null ? null : key.GetValue(name);
                }
            }
            catch { return null; }
        }

        public static string RegistryKeyLastWriteTime(RegistryHive hive, string subkey, RegistryView view = RegistryView.Registry64)
        {
            if (!OperatingSystem.IsWindows()) return "";
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(hive, view))
                using (var key = baseKey.OpenSubKey(subkey))
                {
                    if (key == null) return "";
                    long fileTime;
                    uint classLength = 0;
                    uint subKeyCount, maxSubKeyLen, maxClassLen, valueCount, maxValueNameLen, maxValueLen, securityDescriptor;
                    int rc = RegQueryInfoKey(key.Handle, null, ref classLength, IntPtr.Zero, out subKeyCount, out maxSubKeyLen, out maxClassLen, out valueCount, out maxValueNameLen, out maxValueLen, out securityDescriptor, out fileTime);
                    if (rc != 0 || fileTime <= 0) return "";
                    return DateTime.FromFileTimeUtc(fileTime).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
                }
            }
            catch { return ""; }
        }

        public static string RegistryFileTimeValueToString(object value)
        {
            try
            {
                long fileTime = 0;
                if (value is long l) fileTime = l;
                else if (value is int i) fileTime = i;
                else if (value is byte[] bytes && bytes.Length >= 8) fileTime = BitConverter.ToInt64(bytes, 0);
                else if (value is string s && long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsed)) fileTime = parsed;
                if (fileTime <= 0) return "";
                return DateTime.FromFileTimeUtc(fileTime).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            }
            catch { return ""; }
        }

        public static string ReportCategoryLabel(string category)
        {
            switch (category ?? "")
            {
                case "File Name Scan": return "File/folder name detections";
                case "Browser History": return "Browser/domain keyword detections";
                case "Installed Programs": return "Installed programs and tools";
                case "Execution Evidence": return "Execution evidence";
                case "Browser Source/Download Evidence": return "Browser source/download evidence";
                case "Runtime/Startup": return "Running processes, services, drivers, and startup";
                case "Source Projects": return "Cheat software/source/build evidence";
                case "Boot Security": return "Windows boot security";
                case "Security Center": return "Windows Security Center";
                case "Hardware Identity": return "Hardware identity";
                case "External Devices": return "External USB devices";
                case "Drivers": return "Loaded drivers";
                case "Network": return "Network usage";
                case "Display": return "Display devices";
                case "Compatibility": return "Windows compatibility";
                default: return category ?? "";
            }
        }

        public static string SeverityCssClass(Severity severity)
        {
            return "sev-" + severity.ToString().ToLowerInvariant();
        }

        public static string ConcernCssClass(string concern)
        {
            string lower = ToLowerSafe(concern);
            if (lower.Contains("critical")) return "concern-critical";
            if (lower.Contains("high")) return "concern-high";
            if (lower.Contains("medium")) return "concern-medium";
            if (lower.Contains("low")) return "concern-low";
            return "concern-clean";
        }

        public static string VerdictCssClass(string level)
        {
            string lower = ToLowerSafe(level);
            if (lower.Contains("critical")) return "verdict-critical";
            if (lower.Contains("high")) return "verdict-high";
            if (lower.Contains("medium")) return "verdict-medium";
            if (lower.Contains("low")) return "verdict-low";
            return "verdict-clean";
        }

        public static void SortEvidence<T>(List<T> items, Func<T, int> score, Func<T, int> confidence, Func<T, Severity> severity)
        {
            items.Sort((a, b) =>
            {
                int cmp = score(b).CompareTo(score(a));
                if (cmp != 0) return cmp;
                cmp = confidence(b).CompareTo(confidence(a));
                if (cmp != 0) return cmp;
                return severity(b).CompareTo(severity(a));
            });
        }

        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_NONE = 0;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_STATEACTION_VERIFY = 1;
        private const uint WTD_STATEACTION_CLOSE = 2;
        private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00000004;

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegQueryInfoKey(
            SafeRegistryHandle hKey,
            StringBuilder lpClass,
            ref uint lpcchClass,
            IntPtr lpReserved,
            out uint lpcSubKeys,
            out uint lpcbMaxSubKeyLen,
            out uint lpcbMaxClassLen,
            out uint lpcValues,
            out uint lpcbMaxValueNameLen,
            out uint lpcbMaxValueLen,
            out uint lpcbSecurityDescriptor,
            out long lpftLastWriteTime);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            [MarshalAs(UnmanagedType.LPWStr)] public string pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

    }
}
