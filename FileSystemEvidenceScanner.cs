using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace GamerIntegrity
{
    internal static class FileSystemEvidenceScanner
    {
        private const int MaxFileNameMatches = 2500;
        private const int MaxScannedFileSystemEntries = 250000;

        public static List<FileNameMatch> ScanScopedFileNames(ScanReport report)
        {
            var roots = BuildScanRoots();
            var rules = Rules.FileNameRules();
            var matches = new List<FileNameMatch>();
            int seen = 0;
            foreach (string root in roots)
            {
                if (!Directory.Exists(root))
                {
                    report.AddLimitation("File scan", "Root unavailable", root, "Configured scan root was not available at scan time.", Severity.Info);
                    continue;
                }

                foreach (string entry in SafeEnumerateFileSystemEntries(root, report))
                {
                    if (++seen > MaxScannedFileSystemEntries || matches.Count >= MaxFileNameMatches)
                    {
                        report.AddLimitation("File scan", "Scope cap", root, "File/folder scan stopped after reaching the configured safety cap. Some later paths were not enumerated.", Severity.Low);
                        break;
                    }
                    string name = Path.GetFileName(entry);
                    var best = ScannerService.BestRuleMatch(name, rules);
                    best = ScannerService.AdjustRuleForEvidenceContext(best, entry, "FileName");
                    if (best == null) continue;
                    if (IsLikelyBenignFileNameMatch(entry, best)) continue;
                    matches.Add(new FileNameMatch
                    {
                        Path = entry,
                        Token = best.Token,
                        Category = best.Category,
                        Label = best.Label,
                        Severity = best.Severity,
                        Confidence = best.Confidence,
                        Score = best.Score,
                        LastWriteTime = ScannerHelpers.EntryLastWriteTimeString(entry)
                    });
                }
                if (seen > MaxScannedFileSystemEntries || matches.Count >= MaxFileNameMatches) break;
            }
            ScannerHelpers.SortEvidence(matches, m => m.Score, m => m.Confidence, m => m.Severity);
            if (matches.Count > 0)
            {
                var sample = string.Join("\n", matches.Take(16).Select(m => "- " + m.Label + ": " + m.Path));
                report.AddFinding("File Name Scan", "File/folder name detections found", sample, matches.Max(m => m.Severity), Math.Min(95, matches.Max(m => m.Confidence)), Math.Min(125, matches.Sum(m => m.Score)));
            }
            else report.AddFinding("File Name Scan", "No scoped file/folder name detections found", "Common user, developer, and download locations were checked against the local indicator list.", Severity.Info, 65, 0);
            return matches;
        }

        private static List<string> BuildScanRoots()
        {
            var roots = new List<string>();
            Action<string> add = p => { if (!string.IsNullOrWhiteSpace(p) && Directory.Exists(p) && !roots.Contains(p, StringComparer.OrdinalIgnoreCase)) roots.Add(p); };
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            add(Path.Combine(userProfile, "Downloads"));
            add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            add(Path.Combine(userProfile, "source"));
            add(Path.Combine(userProfile, "repos"));
            add(Path.Combine(userProfile, "Projects"));
            add(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));
            add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            return roots;
        }

        private static IEnumerable<string> SafeEnumerateFileSystemEntries(string root, ScanReport report)
        {
            var pending = new Stack<string>();
            if (!string.IsNullOrWhiteSpace(root)) pending.Push(root);

            while (pending.Count > 0)
            {
                string dir = pending.Pop();
                if (ShouldSkipDirectory(dir)) continue;

                foreach (string f in SafeEnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly, report))
                {
                    yield return f;
                }

                foreach (string d in SafeEnumerateDirectories(dir, report))
                {
                    yield return d;
                    if (!ShouldSkipDirectory(d)) pending.Push(d);
                }
            }
        }

        private static IEnumerable<string> SafeEnumerateFiles(string dir, string pattern, SearchOption option, ScanReport report)
        {
            if (string.IsNullOrWhiteSpace(dir)) yield break;

            var pending = new Stack<string>();
            pending.Push(dir);
            string safePattern = string.IsNullOrWhiteSpace(pattern) ? "*" : pattern;

            while (pending.Count > 0)
            {
                string current = pending.Pop();
                string[] files = Array.Empty<string>();
                try { files = Directory.GetFiles(current, safePattern); }
                catch (Exception ex) { AddEnumerationLimitation(report, current, "Files could not be listed: " + ex.Message); }
                foreach (string file in files) yield return file;

                if (option != SearchOption.AllDirectories) continue;

                string[] dirs = Array.Empty<string>();
                try { dirs = Directory.GetDirectories(current); }
                catch (Exception ex) { AddEnumerationLimitation(report, current, "Folders could not be listed: " + ex.Message); }
                foreach (string child in dirs)
                {
                    if (!IsReparsePoint(child)) pending.Push(child);
                }
            }
        }

        private static IEnumerable<string> SafeEnumerateDirectories(string dir, ScanReport report)
        {
            if (string.IsNullOrWhiteSpace(dir)) yield break;

            string[] dirs = Array.Empty<string>();
            try { dirs = Directory.GetDirectories(dir); }
            catch (Exception ex) { AddEnumerationLimitation(report, dir, "Folders could not be listed: " + ex.Message); }
            foreach (string child in dirs)
            {
                if (!IsReparsePoint(child)) yield return child;
            }
        }

        private static void AddEnumerationLimitation(ScanReport report, string path, string message)
        {
            if (report == null) return;
            if (report.Limitations.Count(l => string.Equals(l.Source, "File system", StringComparison.OrdinalIgnoreCase)) >= 80) return;
            report.AddLimitation("File system", "File scan", path, ScannerHelpers.CollapseWhitespaceForDisplay(message), Severity.Low);
        }

        private static bool IsReparsePoint(string path)
        {
            try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
            catch { return true; }
        }

        private static bool ShouldSkipDirectory(string path)
        {
            string lower = ScannerHelpers.ToLowerSafe(path);
            string name = ScannerHelpers.ToLowerSafe(Path.GetFileName(path));
            if (name == "node_modules" || name == ".git" || name == ".vs" || name == "packages" || name == "obj" || name == "temp" || name == "cache") return true;
            if (lower.Contains(@"\windowsapps\") || lower.Contains(@"\program files\windowsapps")) return true;
            if (lower.Contains(@"\windows defender advanced threat protection\") || lower.Contains(@"\microsoft\windows defender\")) return true;
            if (lower.Contains(@"\gamerintegrity_wpf_") || lower.Contains(@"\gamerintegrity\release\reports\")) return true;
            return false;
        }

        private static bool IsLikelyBenignFileNameMatch(string path, FileNameRule rule)
        {
            string lower = ScannerHelpers.ToLowerSafe(path);
            string fileName = ScannerHelpers.ToLowerSafe(Path.GetFileName(path));
            string token = ScannerHelpers.ToLowerSafe(rule == null ? "" : rule.Token);
            if (token.Equals("loader", StringComparison.OrdinalIgnoreCase) && (lower.Contains("bootloader") || lower.Contains("classloader"))) return true;
            if (token.Equals("cleaner", StringComparison.OrdinalIgnoreCase) && (lower.Contains("disk cleanup") || lower.Contains("ccleaner browser"))) return true;
            if (lower.Contains(@"\program files\windowsapps\") || lower.Contains(@"\program files (x86)\windowsapps\")) return true;
            if (lower.Contains(@"\windows defender advanced threat protection\") || lower.Contains(@"\microsoft\windows defender\")) return true;
            if (lower.Contains("wingetdownloader.exe") || lower.Contains("sensesampleuploader.exe")) return true;
            if (lower.Contains("gamerintegrity_wpf_v") && lower.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) return true;
            if ((token == "trace" || token == "traces") && lower.Contains("gamerintegrity")) return true;
            if (IsSourceFileNameToken(token) && !fileName.EndsWith(token, StringComparison.OrdinalIgnoreCase)) return true;
            if (IsCommonAssetOrWebFile(fileName) && IsSourceFileNameToken(token)) return true;
            if ((token == "radar" || token == "radar.h") && Regex.IsMatch(lower, @"\b(charts?|dashboard|graph|analytics)[-_]?radar\.(html|js|css)$", RegexOptions.IgnoreCase)) return true;
            return false;
        }

        private static bool IsSourceFileNameToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return false;
            return Regex.IsMatch(token, @"\.(h|hpp|cpp|cxx|cc|cs|lua|py|json)$", RegexOptions.IgnoreCase);
        }

        private static bool IsCommonAssetOrWebFile(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName)) return false;
            return Regex.IsMatch(fileName, @"\.(png|jpg|jpeg|gif|webp|ico|svg|html|htm|css)$", RegexOptions.IgnoreCase);
        }
    }
}
