using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace GamerIntegrity
{
    public static class ScannerService
    {
        private const int MaxHistoryBytes = 96 * 1024 * 1024;

        public static ScanResult Run(ScanOptions options, IProgress<ScanProgress> progress)
        {
            options = options ?? new ScanOptions();
            string outputDirectory = string.IsNullOrWhiteSpace(options.OutputDirectory) ? "." : options.OutputDirectory;
            if (options.WriteReports)
            {
                Directory.CreateDirectory(outputDirectory);
            }

            var integrity = new ReportIntegrityContext
            {
                ReportId = ScannerHelpers.GenerateReportId(),
                ScanStartTime = ScannerHelpers.CurrentLocalTimestamp(),
                ComputerName = ScannerHelpers.SafeComputerName(),
                UserName = ScannerHelpers.SafeUserName(),
                ScannerVersion = ScannerHelpers.ReleaseVersion + " / " + ScannerHelpers.EvidenceModelVersion
            };

            var report = new ScanReport();
            var drivers = new List<DriverInfo>();
            var hardwareRecords = new List<HardwareRecord>();
            var deviceRecords = new List<DeviceConnectionRecord>();
            var dmaDeviceRecords = new List<DmaDeviceRecord>();
            var fileMatches = new List<FileNameMatch>();
            var installedProgramMatches = new List<FileNameMatch>();
            var browserMatches = new List<BrowserHistoryMatch>();
            var browserHistorySources = new List<BrowserHistorySource>();
            var executionArtifacts = new List<ExecutionArtifact>();
            var browserDownloadMatches = new List<BrowserDownloadMatch>();
            var runtimeArtifacts = new List<RuntimeArtifact>();
            var sourceProjects = new List<SourceProjectSummary>();
            var cheatingTimeline = new List<CheatingTimelineEvent>();

            try
            {
                Notify(progress, 3, "Starting offline scan...");
                CollectRuntimePrivilegeInfo(report);

                Notify(progress, 10, "Checking Windows and admin access...");
                CollectOsCompatibilityInfo(report);
                Notify(progress, 14, "Windows and admin access checked.");

                Notify(progress, 22, "Reading display and network inventory...");
                CollectNetworkAndDisplayInfo(report);
                Notify(progress, 26, "Display and network inventory checked.");

                Notify(progress, 34, "Checking Windows Security status...");
                CollectAntivirusInfo(report);
                Notify(progress, 38, "Windows Security status checked.");

                Notify(progress, 46, "Checking boot security, TPM, kernel settings, and driver blocklist...");
                CollectBootSecurityInfo(report);
                Notify(progress, 50, "Boot security settings checked.");

                Notify(progress, 54, "Checking installed tools and reverse-engineering apps...");
                installedProgramMatches = ScanInstalledProgramIndicators(report);
                Notify(progress, 58, "Installed tools check complete: " + installedProgramMatches.Count + " flagged tool/program detection(s).");

                Notify(progress, 60, "Checking launch traces from AmCache and Prefetch...");
                executionArtifacts = ScanAmCacheAndPrefetchEvidence(report);
                Notify(progress, 62, "Launch trace check complete: " + executionArtifacts.Count + " AmCache/Prefetch trace(s).");

                Notify(progress, 64, "Checking startup items, services, tasks, and recent app activity...");
                runtimeArtifacts = ScanRuntimeStartupServiceEvidence(report);
                Notify(progress, 66, "Startup and usage trace check complete: " + runtimeArtifacts.Count + " active or persistent artifact(s).");

                Notify(progress, 68, "Checking driver inventory, signatures, and embedded vulnerable-driver catalog...");
                drivers = CollectDriverInfo(report);
                Notify(progress, 72, "Driver inventory complete: " + drivers.Count + " driver service(s) inspected; " + drivers.Count(d => d.KnownVulnerableDriver) + " embedded catalog match(es).");

                Notify(progress, 76, "Collecting hardware identity records...");
                CollectHardwareIdentityInfo(report, hardwareRecords);
                Notify(progress, 79, "Hardware identity check complete: " + hardwareRecords.Count + " record(s) captured.");

                Notify(progress, 80, "Checking DMA-capable PCIe, Thunderbolt, and USB4 device context...");
                CollectDmaPcieDeviceInfo(report, dmaDeviceRecords);
                Notify(progress, 83, "DMA / PCIe review complete: " + dmaDeviceRecords.Count + " context record(s) captured.");

                Notify(progress, 84, "Checking USB and external-device history...");
                CollectExternalDeviceInfo(report, deviceRecords);
                Notify(progress, 86, "USB history check complete: " + deviceRecords.Count + " device record(s) captured.");

                Notify(progress, 88, "Checking local browser SQLite history and download records...");
                var browserScan = BrowserScanner.Scan(report);
                browserHistorySources = browserScan.Sources;
                browserMatches = browserScan.HistoryMatches;
                browserDownloadMatches = browserScan.DownloadMatches;
                Notify(progress, 92, "Browser SQLite check complete: " + browserMatches.Count + " keyword detection(s), " + browserDownloadMatches.Count + " source/download record(s), " + browserHistorySources.Count + " profile(s).");

                if (options.IncludeFileNameScan)
                {
                    Notify(progress, 93, "Checking common user folders for cheat/source/build names...");
                    fileMatches = FileSystemEvidenceScanner.ScanScopedFileNames(report);
                    Notify(progress, 95, "Files and folders check complete: " + fileMatches.Count + " match(es).");
                }

                AddScanLimitationsSummary(report);

                Notify(progress, 96, "Grouping related evidence and building the timeline...");
                sourceProjects = AnalyzeSourceProjects(report, fileMatches, executionArtifacts, runtimeArtifacts);
                cheatingTimeline = BuildCheatingTimeline(fileMatches, browserMatches, browserDownloadMatches, executionArtifacts, runtimeArtifacts, sourceProjects);

                integrity.ScanEndTime = ScannerHelpers.CurrentLocalTimestamp();

                string htmlPath = Path.Combine(outputDirectory, "GamerIntegrity_Report.html");
                string jsonPath = Path.Combine(outputDirectory, "GamerIntegrity_Report.json");
                string redactedHtmlPath = Path.Combine(outputDirectory, "GamerIntegrity_Report_Redacted.html");
                string redactedJsonPath = Path.Combine(outputDirectory, "GamerIntegrity_Report_Redacted.json");
                integrity.ManifestPath = Path.Combine(outputDirectory, "GamerIntegrity_Report_Integrity.json");
                string redactedManifestPath = Path.Combine(outputDirectory, "GamerIntegrity_Report_Redacted_Integrity.json");

                Notify(progress, 98, "Preparing the in-app report view...");
                string jsonContent = ReportWriter.BuildJsonReport(report, drivers, hardwareRecords, deviceRecords, dmaDeviceRecords, installedProgramMatches, fileMatches,
                    browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects,
                    cheatingTimeline, integrity, false);
                string htmlContent = ReportWriter.BuildHtmlReport(report, drivers, hardwareRecords, deviceRecords, dmaDeviceRecords, installedProgramMatches, fileMatches,
                    browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects,
                    cheatingTimeline, integrity, false);
                string redactedJsonContent = ReportWriter.BuildJsonReport(report, drivers, hardwareRecords, deviceRecords, dmaDeviceRecords, installedProgramMatches, fileMatches,
                    browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects,
                    cheatingTimeline, integrity, true);
                string redactedHtmlContent = ReportWriter.BuildHtmlReport(report, drivers, hardwareRecords, deviceRecords, dmaDeviceRecords, installedProgramMatches, fileMatches,
                    browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects,
                    cheatingTimeline, integrity, true);
                var redactedCtx = new ReportIntegrityContext
                {
                    ReportId = integrity.ReportId,
                    ScanStartTime = integrity.ScanStartTime,
                    ScanEndTime = integrity.ScanEndTime,
                    ComputerName = integrity.ComputerName,
                    UserName = integrity.UserName,
                    ScannerVersion = integrity.ScannerVersion,
                    ManifestPath = redactedManifestPath
                };

                bool builtReports = !string.IsNullOrWhiteSpace(jsonContent) && !string.IsNullOrWhiteSpace(htmlContent) &&
                    !string.IsNullOrWhiteSpace(redactedJsonContent) && !string.IsNullOrWhiteSpace(redactedHtmlContent);

                if (options.WriteReports)
                {
                    Notify(progress, 99, "Exporting the selected report files...");
                    bool wroteJson = ReportWriter.WriteReportContent(jsonPath, jsonContent);
                    bool wroteHtml = ReportWriter.WriteReportContent(htmlPath, htmlContent);
                    bool wroteRedactedJson = ReportWriter.WriteReportContent(redactedJsonPath, redactedJsonContent);
                    bool wroteRedactedHtml = ReportWriter.WriteReportContent(redactedHtmlPath, redactedHtmlContent);
                    bool wroteManifest = ReportWriter.WriteReportIntegrityManifest(integrity, htmlPath, jsonPath, integrity.ManifestPath, false);
                    bool wroteRedactedManifest = ReportWriter.WriteReportIntegrityManifest(redactedCtx, redactedHtmlPath, redactedJsonPath, redactedManifestPath, true);
                    builtReports = builtReports && wroteJson && wroteHtml && wroteRedactedJson && wroteRedactedHtml && wroteManifest && wroteRedactedManifest;
                }

                int code = builtReports ? 0 : 2;
                var result = new ScanResult
                {
                    ExitCode = code,
                    OutputDirectory = outputDirectory,
                    HtmlReportPath = options.WriteReports ? htmlPath : "",
                    JsonReportPath = options.WriteReports ? jsonPath : "",
                    RedactedHtmlReportPath = options.WriteReports ? redactedHtmlPath : "",
                    RedactedJsonReportPath = options.WriteReports ? redactedJsonPath : "",
                    IntegrityManifestPath = options.WriteReports ? integrity.ManifestPath : "",
                    RedactedIntegrityManifestPath = options.WriteReports ? redactedManifestPath : "",
                    HtmlReportContent = htmlContent,
                    JsonReportContent = jsonContent,
                    RedactedHtmlReportContent = redactedHtmlContent,
                    RedactedJsonReportContent = redactedJsonContent,
                    IntegrityContext = integrity,
                    RedactedIntegrityContext = redactedCtx
                };
                result.SummaryText = BuildSummaryText(report, hardwareRecords, deviceRecords, dmaDeviceRecords, fileMatches, browserMatches, browserHistorySources,
                    executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects, cheatingTimeline, outputDirectory, htmlPath, jsonPath,
                    redactedHtmlPath, redactedJsonPath, redactedManifestPath, integrity);
                Notify(progress, 100, code == 0 ? "Scan complete. Choose Redacted or Non-Redacted to view results." : "Scan complete, but results could not be prepared.");
                return result;
            }
            catch (Exception ex)
            {
                if (options.WriteReports)
                {
                    try
                    {
                        Directory.CreateDirectory(outputDirectory);
                        File.WriteAllText(Path.Combine(outputDirectory, "GamerIntegrity_Error.txt"), ex.ToString(), Encoding.UTF8);
                    }
                    catch { }
                }

                return new ScanResult { ExitCode = 3, OutputDirectory = outputDirectory, SummaryText = ex.Message };
            }
        }

        private static void Notify(IProgress<ScanProgress> progress, int percent, string stage)
        {
            progress?.Report(new ScanProgress { Percent = ScannerHelpers.Clamp(percent, 0, 100), Stage = stage ?? "" });
        }

        private static void CollectRuntimePrivilegeInfo(ScanReport report)
        {
            bool elevated = false;
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch { }

            report.AddFinding("Compatibility", elevated ? "Scanner is running elevated" : "Scanner is not running elevated",
                elevated
                    ? "The process is running with administrator privileges, so machine-level registry, driver, service, and security checks can use their highest-fidelity paths."
                    : "The process is not running with administrator privileges. User-level checks will still run, but protected registry, driver, service, and security data may be incomplete.",
                elevated ? Severity.Info : Severity.Low, elevated ? 90 : 65, elevated ? 0 : 8);
        }

        private static void CollectOsCompatibilityInfo(ScanReport report)
        {
            var rows = ScannerHelpers.WmiQueryRows("ROOT\\CIMV2", "SELECT Caption,Version,BuildNumber FROM Win32_OperatingSystem", "Caption", "Version", "BuildNumber");
            string caption = rows.Count > 0 ? ScannerHelpers.WmiValue(rows[0], "Caption") : Environment.OSVersion.VersionString;
            string version = rows.Count > 0 ? ScannerHelpers.WmiValue(rows[0], "Version") : Environment.OSVersion.Version.ToString();
            string build = rows.Count > 0 ? ScannerHelpers.WmiValue(rows[0], "BuildNumber") : Environment.OSVersion.Version.Build.ToString(CultureInfo.InvariantCulture);
            report.AddFinding("Compatibility", "Windows compatibility details captured", "OS: " + caption + " | Version: " + version + " | Build: " + build + ".", Severity.Info, 90, 0);
        }

        private static void CollectNetworkAndDisplayInfo(ScanReport report)
        {
            var videoRows = ScannerHelpers.WmiQueryRows("ROOT\\CIMV2", "SELECT Name,DriverVersion,VideoProcessor FROM Win32_VideoController", "Name", "DriverVersion", "VideoProcessor");
            if (videoRows.Count == 0)
                report.AddFinding("Display", "Display adapter inventory unavailable", "No Win32_VideoController rows were returned.", Severity.Info, 40, 0);
            else
            {
                var names = videoRows.Select(r => ScannerHelpers.WmiValue(r, "Name")).Where(s => !string.IsNullOrWhiteSpace(s)).Take(6);
                report.AddFinding("Display", "Display adapter inventory captured", "Display adapters: " + string.Join("; ", names) + ".", Severity.Info, 80, 0);
            }

            var nicRows = ScannerHelpers.WmiQueryRows("ROOT\\CIMV2", "SELECT Description,MACAddress,IPEnabled FROM Win32_NetworkAdapterConfiguration WHERE MACAddress IS NOT NULL", "Description", "MACAddress", "IPEnabled");
            report.AddFinding("Network", "Network adapter inventory captured", "Network adapters with MAC values: " + nicRows.Count + ".", Severity.Info, 70, 0);
        }

        private static void CollectAntivirusInfo(ScanReport report)
        {
            var rows = ScannerHelpers.WmiQueryRows("ROOT\\SecurityCenter2", "SELECT displayName,productState,pathToSignedProductExe FROM AntivirusProduct", "displayName", "productState", "pathToSignedProductExe");
            if (rows.Count == 0)
            {
                report.AddFinding("Security Center", "No antivirus product reported by Security Center", "Windows Security Center did not return any AntivirusProduct rows. This can happen on hardened, damaged, or non-standard systems.", Severity.Medium, 65, 20);
                return;
            }

            string names = string.Join("; ", rows.Select(r => ScannerHelpers.WmiValue(r, "displayName")).Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().Take(10));
            report.AddFinding("Security Center", "Antivirus products reported", "Security Center products: " + names + ". Product rows: " + rows.Count + ".", Severity.Info, 80, 0);
        }

        private static void CollectBootSecurityInfo(ScanReport report)
        {
            int? secureBoot = ScannerHelpers.ReadRegistryDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
            if (secureBoot.HasValue)
            {
                report.AddFinding("Boot Security", secureBoot.Value == 1 ? "Secure Boot enabled" : "Secure Boot disabled", "Registry UEFISecureBootEnabled=" + secureBoot.Value + ".", secureBoot.Value == 1 ? Severity.Info : Severity.Medium, 75, secureBoot.Value == 1 ? 0 : 18);
            }
            else report.AddFinding("Boot Security", "Secure Boot state unavailable", "Secure Boot registry state could not be read.", Severity.Info, 40, 0);

            var tpmRows = ScannerHelpers.WmiQueryRows("ROOT\\CIMV2\\Security\\MicrosoftTpm", "SELECT IsEnabled_InitialValue,IsActivated_InitialValue,IsOwned_InitialValue FROM Win32_Tpm", "IsEnabled_InitialValue", "IsActivated_InitialValue", "IsOwned_InitialValue");
            if (tpmRows.Count > 0)
            {
                string enabled = ScannerHelpers.WmiValue(tpmRows[0], "IsEnabled_InitialValue");
                report.AddFinding("Boot Security", enabled.Equals("True", StringComparison.OrdinalIgnoreCase) ? "TPM enabled" : "TPM not enabled", "TPM WMI row: Enabled=" + enabled + ", Activated=" + ScannerHelpers.WmiValue(tpmRows[0], "IsActivated_InitialValue") + ", Owned=" + ScannerHelpers.WmiValue(tpmRows[0], "IsOwned_InitialValue") + ".", enabled.Equals("True", StringComparison.OrdinalIgnoreCase) ? Severity.Info : Severity.Low, 70, enabled.Equals("True", StringComparison.OrdinalIgnoreCase) ? 0 : 5);
            }

            int? vbs = ScannerHelpers.ReadRegistryDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity");
            if (vbs.HasValue) report.AddFinding("Boot Security", vbs.Value == 1 ? "Virtualization-based security configured" : "Virtualization-based security not configured", "Registry EnableVirtualizationBasedSecurity=" + vbs.Value + ".", Severity.Info, 65, 0);

            int? hvci = ScannerHelpers.ReadRegistryDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled");
            if (hvci.HasValue) report.AddFinding("Boot Security", hvci.Value == 1 ? "Memory integrity/HVCI enabled" : "Memory integrity/HVCI disabled", "Registry HVCI Enabled=" + hvci.Value + ".", hvci.Value == 1 ? Severity.Info : Severity.Low, 65, hvci.Value == 1 ? 0 : 5);

            int? blocklist = ScannerHelpers.ReadRegistryDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable");
            if (blocklist.HasValue) report.AddFinding("Boot Security", blocklist.Value == 1 ? "Microsoft vulnerable driver blocklist enabled" : "Microsoft vulnerable driver blocklist disabled", "Registry VulnerableDriverBlocklistEnable=" + blocklist.Value + ".", blocklist.Value == 1 ? Severity.Info : Severity.Medium, 70, blocklist.Value == 1 ? 0 : 15);

            string bcd = RunCommandCapture("bcdedit /enum {current}");
            if (!string.IsNullOrWhiteSpace(bcd))
            {
                bool testSigning = BcdOptionEnabled(bcd, "testsigning");
                bool noIntegrityChecks = BcdOptionEnabled(bcd, "nointegritychecks");
                bool kernelDebug = BcdOptionEnabled(bcd, "debug");

                report.AddFinding("Boot Security", testSigning ? "Kernel test-signing enabled" : "Kernel test-signing is not enabled",
                    testSigning ? "BCD output has testsigning set to Yes for the current loader." : "BCD output did not show testsigning enabled for the current loader.",
                    testSigning ? Severity.High : Severity.Info, testSigning ? 84 : 70, testSigning ? 45 : 0);

                if (noIntegrityChecks)
                    report.AddFinding("Boot Security", "Kernel integrity checks disabled", "BCD output has nointegritychecks set to Yes for the current loader.", Severity.High, 84, 45);
                else
                    report.AddFinding("Boot Security", "Kernel integrity checks are not disabled", "BCD output did not show nointegritychecks enabled for the current loader.", Severity.Info, 68, 0);

                if (kernelDebug)
                    report.AddFinding("Boot Security", "Kernel debugging enabled", "BCD output has debug set to Yes for the current loader.", Severity.Medium, 74, 25);
                else
                    report.AddFinding("Boot Security", "Kernel debugging is not enabled", "BCD output did not show kernel debugging enabled for the current loader.", Severity.Info, 68, 0);
            }
            else
            {
                report.AddFinding("Boot Security", "BCD state could not be read", "bcdedit output could not be captured. Run as administrator for the most complete boot-security posture.", Severity.Low, 45, 5);
            }
        }

        private static string RunCommandCapture(string command)
        {
            try
            {
                var psi = new ProcessStartInfo("cmd.exe", "/c " + command)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using (var p = Process.Start(psi))
                {
                    if (p == null) return "";
                    string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                    p.WaitForExit(8000);
                    return output;
                }
            }
            catch { return ""; }
        }

        private static bool BcdOptionEnabled(string bcdOutput, string optionName)
        {
            if (string.IsNullOrWhiteSpace(bcdOutput) || string.IsNullOrWhiteSpace(optionName)) return false;
            foreach (string rawLine in bcdOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string line = rawLine.Trim();
                if (!line.StartsWith(optionName, StringComparison.OrdinalIgnoreCase)) continue;
                string[] parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                string value = parts[parts.Length - 1];
                return value.Equals("yes", StringComparison.OrdinalIgnoreCase) || value.Equals("true", StringComparison.OrdinalIgnoreCase) || value.Equals("1", StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }

        private static List<FileNameMatch> ScanInstalledProgramIndicators(ScanReport report)
        {
            var rules = Rules.InstalledProgramRules();
            var matches = new List<FileNameMatch>();
            foreach (var item in EnumerateInstalledPrograms())
            {
                string display = item.Item1;
                string location = item.Item2;
                string evidenceValue = display + " " + location;
                FileNameRule best = BestRuleMatch(evidenceValue, rules);
                best = AdjustRuleForEvidenceContext(best, evidenceValue, "Installed");
                if (best == null) continue;
                matches.Add(new FileNameMatch
                {
                    Path = string.IsNullOrWhiteSpace(location) ? display : display + " | " + location,
                    Token = best.Token,
                    Category = best.Category,
                    Label = best.Label,
                    Severity = best.Severity,
                    Confidence = best.Confidence,
                    Score = best.Score
                });
            }
            DeduplicateInstalledProgramMatches(matches);
            ScannerHelpers.SortEvidence(matches, m => m.Score, m => m.Confidence, m => m.Severity);
            if (matches.Count > 0)
            {
                var sample = string.Join("\n", matches.Take(10).Select(m => "- " + m.Label + ": " + m.Path));
                report.AddFinding("Installed Programs", "Installed cheat/tool indicators found", sample, matches.Max(m => m.Severity), Math.Min(95, matches.Max(m => m.Confidence)), Math.Min(100, matches.Sum(m => Math.Max(0, m.Score))));
            }
            else report.AddFinding("Installed Programs", "No installed cheat/tool indicators found", "Installed-program registry entries were checked against the local indicator list.", Severity.Info, 70, 0);
            return matches;
        }

        private static IEnumerable<Tuple<string, string>> EnumerateInstalledPrograms()
        {
            string uninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
                foreach (string name in ScannerHelpers.EnumerateSubKeyNames(RegistryHive.LocalMachine, uninstall, view))
                {
                    var values = ScannerHelpers.ReadRegistryValues(RegistryHive.LocalMachine, uninstall + "\\" + name, view);
                    yield return Tuple.Create(Value(values, "DisplayName"), Value(values, "InstallLocation"));
                }
            foreach (string name in ScannerHelpers.EnumerateSubKeyNames(RegistryHive.CurrentUser, uninstall, RegistryView.Default))
            {
                var values = ScannerHelpers.ReadRegistryValues(RegistryHive.CurrentUser, uninstall + "\\" + name, RegistryView.Default);
                yield return Tuple.Create(Value(values, "DisplayName"), Value(values, "InstallLocation"));
            }
        }

        private static void DeduplicateInstalledProgramMatches(List<FileNameMatch> matches)
        {
            var groups = matches.GroupBy(m => InstalledProgramKey(m.Path), StringComparer.OrdinalIgnoreCase).ToList();
            matches.Clear();
            foreach (var group in groups)
            {
                var best = group.OrderByDescending(m => m.Score).ThenByDescending(m => m.Confidence).ThenByDescending(m => m.Severity).First();
                int count = group.Count();
                if (count > 1 && best.Path.IndexOf("seen in", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    best.Path = best.Path + " (seen in " + count.ToString(CultureInfo.InvariantCulture) + " uninstall entries)";
                }
                matches.Add(best);
            }
        }

        private static string InstalledProgramKey(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "";
            string name = value;
            int pipe = name.IndexOf(" | ", StringComparison.Ordinal);
            if (pipe >= 0) name = name.Substring(0, pipe);
            name = Regex.Replace(name, @"\s*\(remove only\)\s*", "", RegexOptions.IgnoreCase);
            name = Regex.Replace(name, @"\s*\(seen in \d+ uninstall entries\)\s*", "", RegexOptions.IgnoreCase);
            name = Regex.Replace(name, @"\s+", " ").Trim().ToLowerInvariant();
            return name;
        }

        private static string Value(Dictionary<string, object> values, string key)
        {
            object v;
            return values.TryGetValue(key, out v) && v != null ? ScannerHelpers.Trim(v.ToString()) : "";
        }

        private static List<ExecutionArtifact> ScanAmCacheAndPrefetchEvidence(ScanReport report)
        {
            var artifacts = new List<ExecutionArtifact>();
            var rules = Rules.ExecutionRules();
            ScanPrefetch(artifacts, rules);
            ScanAmCacheRaw(artifacts, rules);
            DeduplicateExecutionArtifacts(artifacts);
            ScannerHelpers.SortEvidence(artifacts, a => a.Score, a => a.Confidence, a => a.Severity);
            if (artifacts.Count > 0)
            {
                var sample = string.Join("\n", artifacts.Take(12).Select(a => "- " + a.Source + ": " + a.Name + " [" + a.Label + "]" + (string.IsNullOrWhiteSpace(a.When) ? "" : " @ " + a.When)));
                report.AddFinding("Execution Evidence", "Execution traces matched cheat/tool indicators", sample, artifacts.Max(a => a.Severity), Math.Min(95, artifacts.Max(a => a.Confidence)), Math.Min(140, artifacts.Sum(a => a.Score)));
            }
            else report.AddFinding("Execution Evidence", "No AmCache/Prefetch execution indicators found", "Prefetch filenames and AmCache bytes were checked against the local indicator list.", Severity.Info, 65, 0);
            return artifacts;
        }

        private static void ScanPrefetch(List<ExecutionArtifact> artifacts, List<FileNameRule> rules)
        {
            string prefetch = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
            if (!Directory.Exists(prefetch)) return;
            foreach (string file in SafeEnumerateFiles(prefetch, "*.pf", SearchOption.TopDirectoryOnly).Take(20000))
            {
                string name = Path.GetFileName(file);
                var best = BestRuleMatch(name, rules);
                best = AdjustRuleForEvidenceContext(best, name, "ExecutionPrefetch");
                if (best == null) continue;
                artifacts.Add(new ExecutionArtifact
                {
                    Source = "Prefetch",
                    Name = name,
                    Path = file,
                    Token = best.Token,
                    Label = best.Label,
                    When = ScannerHelpers.FileTimeString(file),
                    Details = "Prefetch filename matched local indicator token.",
                    Severity = best.Severity,
                    Confidence = Math.Min(95, best.Confidence + 5),
                    Score = best.Score
                });
            }
        }

        private static void ScanAmCacheRaw(List<ExecutionArtifact> artifacts, List<FileNameRule> rules)
        {
            string amcache = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"AppCompat\Programs\Amcache.hve");
            if (!File.Exists(amcache)) return;
            string data = ReadBinaryAsText(amcache, MaxHistoryBytes);
            if (data.Length == 0) return;
            string lower = data.ToLowerInvariant();
            foreach (var rule in rules)
            {
                int pos = lower.IndexOf(rule.Token.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase);
                if (pos < 0) continue;
                string snippet = Snippet(data, pos, rule.Token.Length);
                FileNameRule adjustedRule = AdjustRuleForEvidenceContext(rule, snippet, "ExecutionAmCache");
                if (adjustedRule == null) continue;
                artifacts.Add(new ExecutionArtifact
                {
                    Source = "AmCache",
                    Name = rule.Token,
                    Path = amcache,
                    Token = adjustedRule.Token,
                    Label = adjustedRule.Label,
                    When = ScannerHelpers.FileTimeString(amcache),
                    Details = ScannerHelpers.CollapseWhitespaceForDisplay(snippet),
                    Severity = adjustedRule.Severity,
                    Confidence = Math.Max(50, adjustedRule.Confidence - 8),
                    Score = Math.Max(5, adjustedRule.Score - 10)
                });
            }
        }

        private static void DeduplicateExecutionArtifacts(List<ExecutionArtifact> artifacts)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = artifacts.Count - 1; i >= 0; i--)
            {
                string key = artifacts[i].Source + "|" + artifacts[i].Name + "|" + artifacts[i].Token;
                if (!seen.Add(key)) artifacts.RemoveAt(i);
            }
        }

        private static List<RuntimeArtifact> ScanRuntimeStartupServiceEvidence(ScanReport report)
        {
            var artifacts = new List<RuntimeArtifact>();
            var rules = Rules.ExecutionRules();
            ScanProcesses(artifacts, rules);
            ScanServices(artifacts, rules);
            ScanRunKeys(artifacts, rules);
            ScanScheduledTasks(artifacts, rules);
            ScanUserAssist(artifacts, rules);
            ScanBamDam(artifacts, rules);
            ScanJumpListsAndRecentItems(artifacts, rules);
            ScanShellBags(artifacts, rules);
            ScanRunMruAndRecentDocs(artifacts, rules);
            ScanMountedDevices(artifacts, rules);
            ScanDefenderHistory(artifacts, rules);
            ScanEventLogTextArtifacts(artifacts, rules);
            ScanSrumDatabase(artifacts, rules);
            ScanCleanupIndicators(report);
            artifacts.RemoveAll(IsRuntimeSelfNoise);
            DeduplicateRuntimeArtifacts(artifacts);
            ScannerHelpers.SortEvidence(artifacts, a => a.Score, a => a.Confidence, a => a.Severity);
            if (artifacts.Count > 0)
            {
                var sample = string.Join("\n", artifacts.Take(12).Select(a => "- " + a.SourceType + ": " + a.Name + " [" + a.Label + "] " + a.Path));
                report.AddFinding("Runtime/Startup", "Launch, startup, and retained history indicators found", sample, artifacts.Max(a => a.Severity), Math.Min(95, artifacts.Max(a => a.Confidence)), Math.Min(100, artifacts.Sum(a => a.Score)));
            }
            else report.AddFinding("Runtime/Startup", "No runtime/startup indicators found", "Running processes, services, startup keys, scheduled tasks, UserAssist, BAM/DAM, Jump Lists, ShellBags, mounted devices, Defender history, SRUM, and local event-log text were checked against local indicators.", Severity.Info, 65, 0);
            return artifacts;
        }

        private static bool IsRuntimeSelfNoise(RuntimeArtifact artifact)
        {
            if (artifact == null) return false;
            string combined = (artifact.SourceType ?? "") + " " + (artifact.Name ?? "") + " " + (artifact.Path ?? "") + " " + (artifact.Token ?? "") + " " + (artifact.Label ?? "") + " " + (artifact.Details ?? "");
            return ScannerHelpers.IsGamerIntegritySelfNoise(combined);
        }

        private static void ScanProcesses(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            foreach (var p in Process.GetProcesses())
            {
                using (p)
                {
                    string name = "";
                    string path = "";
                    try { name = p.ProcessName; } catch { }
                    try { path = p.MainModule?.FileName ?? ""; } catch { }
                    string evidenceValue = name + " " + path;
                    var best = BestRuleMatch(evidenceValue, rules);
                    best = AdjustRuleForEvidenceContext(best, evidenceValue, "RuntimeProcess");
                    if (best == null) continue;
                    artifacts.Add(new RuntimeArtifact
                    {
                        SourceType = "Process",
                        Name = name,
                        Path = path,
                        Token = best.Token,
                        Label = best.Label,
                        Details = "Running process matched indicator token.",
                        Severity = best.Severity,
                        Confidence = Math.Min(95, best.Confidence + 5),
                        Score = best.Score
                    });
                }
            }
        }

        private static void ScanServices(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            foreach (ServiceController svc in GetServiceControllersSafe())
            {
                using (svc)
                {
                    string name = "";
                    string display = "";
                    try { name = svc.ServiceName; display = svc.DisplayName; } catch { }
                    string path = GetServiceImagePath(name);
                    string evidenceValue = name + " " + display + " " + path;
                    var best = BestRuleMatch(evidenceValue, rules);
                    best = AdjustRuleForEvidenceContext(best, evidenceValue, "RuntimeService");
                    if (best == null) continue;
                    artifacts.Add(new RuntimeArtifact
                    {
                        SourceType = "Service/Driver",
                        Name = string.IsNullOrWhiteSpace(display) ? name : display,
                        Path = path,
                        Token = best.Token,
                        Label = best.Label,
                        Details = "Service or driver entry matched indicator token.",
                        Severity = best.Severity,
                        Confidence = best.Confidence,
                        Score = best.Score
                    });
                }
            }
        }

        private static IEnumerable<ServiceController> GetServiceControllersSafe()
        {
            var list = new List<ServiceController>();
            try { list.AddRange(ServiceController.GetServices()); } catch { }
            try { list.AddRange(ServiceController.GetDevices()); } catch { }
            return list;
        }

        private static string GetServiceImagePath(string serviceName)
        {
            if (string.IsNullOrWhiteSpace(serviceName)) return "";
            string raw = ScannerHelpers.ReadRegistryString(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\" + serviceName, "ImagePath");
            return ScannerHelpers.NormalizeServiceBinaryPath(raw);
        }

        private static void ScanRunKeys(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            var keys = new[]
            {
                Tuple.Create(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", RegistryView.Default),
                Tuple.Create(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", RegistryView.Default),
                Tuple.Create(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry64),
                Tuple.Create(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", RegistryView.Registry64),
                Tuple.Create(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry32),
                Tuple.Create(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", RegistryView.Registry32)
            };
            foreach (var key in keys)
            {
                foreach (var kv in ScannerHelpers.ReadRegistryValues(key.Item1, key.Item2, key.Item3))
                {
                    string value = kv.Value == null ? "" : kv.Value.ToString();
                    string evidenceValue = kv.Key + " " + value;
                    var best = BestRuleMatch(evidenceValue, rules);
                    best = AdjustRuleForEvidenceContext(best, evidenceValue, "StartupRegistry");
                    if (best == null) continue;
                    artifacts.Add(new RuntimeArtifact
                    {
                        SourceType = "Startup registry",
                        Name = kv.Key,
                        Path = value,
                        Token = best.Token,
                        Label = best.Label,
                        Details = key.Item1 + "\\" + key.Item2 + " (" + key.Item3 + ")",
                        Severity = best.Severity,
                        Confidence = best.Confidence,
                        Score = best.Score
                    });
                }
            }
        }

        private static void ScanScheduledTasks(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            string taskRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
            if (!Directory.Exists(taskRoot)) return;
            int count = 0;
            foreach (string file in SafeEnumerateFiles(taskRoot, "*", SearchOption.AllDirectories))
            {
                if (++count > 20000) break;
                string text = "";
                try { text = File.ReadAllText(file); } catch { }
                if (text.Length == 0) continue;
                string evidenceValue = Path.GetFileName(file) + " " + text;
                var best = BestRuleMatch(evidenceValue, rules);
                best = AdjustRuleForEvidenceContext(best, evidenceValue, "ScheduledTask");
                if (best == null) continue;
                artifacts.Add(new RuntimeArtifact
                {
                    SourceType = "Scheduled task",
                    Name = Path.GetFileName(file),
                    Path = file,
                    Token = best.Token,
                    Label = best.Label,
                    Details = "Scheduled task XML matched indicator token.",
                    When = ScannerHelpers.FileTimeString(file),
                    Severity = best.Severity,
                    Confidence = best.Confidence,
                    Score = best.Score
                });
            }
        }

        private static void ScanUserAssist(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            const string root = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
            foreach (string guid in ScannerHelpers.EnumerateSubKeyNames(RegistryHive.CurrentUser, root, RegistryView.Default).Take(80))
            {
                string countKey = root + "\\" + guid + @"\Count";
                foreach (var kv in ScannerHelpers.ReadRegistryValues(RegistryHive.CurrentUser, countKey, RegistryView.Default))
                {
                    string decoded = Rot13(kv.Key);
                    string evidenceValue = decoded + " " + kv.Key;
                    var best = BestRuleMatch(evidenceValue, rules);
                    best = AdjustRuleForEvidenceContext(best, evidenceValue, "UsageUserAssist");
                    if (best == null) continue;
                    artifacts.Add(new RuntimeArtifact
                    {
                        SourceType = "UserAssist launch history",
                        Name = decoded,
                        Path = decoded,
                        Token = best.Token,
                        Label = best.Label,
                        Details = "Explorer/UserAssist launch history matched an indicator token.",
                        When = ScannerHelpers.RegistryKeyLastWriteTime(RegistryHive.CurrentUser, countKey, RegistryView.Default),
                        Severity = best.Severity,
                        Confidence = best.Confidence,
                        Score = best.Score
                    });
                }
            }
        }

        private static void ScanBamDam(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            var roots = new[]
            {
                Tuple.Create("BAM", @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"),
                Tuple.Create("DAM", @"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings")
            };
            foreach (var root in roots)
            {
                foreach (string sid in ScannerHelpers.EnumerateSubKeyNames(RegistryHive.LocalMachine, root.Item2, RegistryView.Registry64).Take(200))
                {
                    string key = root.Item2 + "\\" + sid;
                    foreach (var kv in ScannerHelpers.ReadRegistryValues(RegistryHive.LocalMachine, key, RegistryView.Registry64))
                    {
                        string valueName = kv.Key ?? "";
                        string evidenceValue = valueName;
                        var best = BestRuleMatch(evidenceValue, rules);
                        best = AdjustRuleForEvidenceContext(best, evidenceValue, "UsageBamDam");
                        if (best == null) continue;
                        artifacts.Add(new RuntimeArtifact
                        {
                            SourceType = root.Item1 + " recent app activity",
                            Name = ScannerHelpers.GetFileNameOnly(valueName),
                            Path = ScannerHelpers.NormalizeKernelModulePath(valueName),
                            Token = best.Token,
                            Label = best.Label,
                            Details = root.Item1 + " retained a recent app activity path for this user SID.",
                            When = ScannerHelpers.RegistryFileTimeValueToString(kv.Value),
                            Severity = best.Severity,
                            Confidence = best.Confidence,
                            Score = best.Score
                        });
                    }
                }
            }
        }

        private static void ScanJumpListsAndRecentItems(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string recent = Path.Combine(roaming, @"Microsoft\Windows\Recent");
            var roots = new[]
            {
                recent,
                Path.Combine(recent, "AutomaticDestinations"),
                Path.Combine(recent, "CustomDestinations")
            };
            int count = 0;
            foreach (string root in roots)
            {
                if (!Directory.Exists(root)) continue;
                foreach (string file in SafeEnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    if (++count > 15000) return;
                    string data = Path.GetFileName(file) + " " + ReadBinaryAsText(file, 2 * 1024 * 1024);
                    var best = BestRuleMatch(data, rules);
                    best = AdjustRuleForEvidenceContext(best, data, "UsageJumpList");
                    if (best == null) continue;
                    artifacts.Add(new RuntimeArtifact
                    {
                        SourceType = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? "Recent item" : "Jump List",
                        Name = Path.GetFileName(file),
                        Path = file,
                        Token = best.Token,
                        Label = best.Label,
                        Details = "Recent item or Jump List content matched an indicator token.",
                        When = ScannerHelpers.FileTimeString(file),
                        Severity = best.Severity,
                        Confidence = Math.Max(45, best.Confidence - 3),
                        Score = Math.Max(3, best.Score - 3)
                    });
                }
            }
        }

        private static void ScanShellBags(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            const string root = @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU";
            ScanRegistryTreeText(artifacts, rules, RegistryHive.CurrentUser, root, RegistryView.Default, "ShellBag folder history", "UsageShellBag", 5000);
        }

        private static void ScanRunMruAndRecentDocs(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            ScanRegistryTreeText(artifacts, rules, RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", RegistryView.Default, "Run box history", "UsageRunMru", 200);
            ScanRegistryTreeText(artifacts, rules, RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", RegistryView.Default, "Recent document history", "UsageRecentDocs", 5000);
            ScanRegistryTreeText(artifacts, rules, RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU", RegistryView.Default, "Open/Save dialog history", "UsageRecentDocs", 5000);
            ScanRegistryTreeText(artifacts, rules, RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU", RegistryView.Default, "Open/Save app history", "UsageRecentDocs", 5000);
        }

        private static void ScanMountedDevices(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            ScanRegistryTreeText(artifacts, rules, RegistryHive.LocalMachine, @"SYSTEM\MountedDevices", RegistryView.Registry64, "Mounted device history", "UsageMountedDevice", 1000);
            ScanRegistryTreeText(artifacts, rules, RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2", RegistryView.Default, "Mounted device history", "UsageMountedDevice", 2000);
        }

        private static void ScanRegistryTreeText(List<RuntimeArtifact> artifacts, List<FileNameRule> rules, RegistryHive hive, string root, RegistryView view, string sourceType, string evidenceKind, int maxKeys)
        {
            int visited = 0;
            var stack = new Stack<string>();
            stack.Push(root);
            while (stack.Count > 0 && visited < maxKeys)
            {
                string keyPath = stack.Pop();
                visited++;
                string keyText = keyPath;
                var values = ScannerHelpers.ReadRegistryValues(hive, keyPath, view);
                foreach (var kv in values)
                {
                    keyText += " " + kv.Key + " " + RegistryValueToSearchText(kv.Value);
                }
                var best = BestRuleMatch(keyText, rules);
                best = AdjustRuleForEvidenceContext(best, keyText, evidenceKind);
                if (best != null)
                {
                    artifacts.Add(new RuntimeArtifact
                    {
                        SourceType = sourceType,
                        Name = keyPath.Substring(Math.Max(0, keyPath.LastIndexOf('\\') + 1)),
                        Path = hive + @"\" + keyPath,
                        Token = best.Token,
                        Label = best.Label,
                        Details = sourceType + " matched an indicator token in local registry history.",
                        When = ScannerHelpers.RegistryKeyLastWriteTime(hive, keyPath, view),
                        Severity = best.Severity,
                        Confidence = Math.Max(40, best.Confidence - 5),
                        Score = Math.Max(2, best.Score - 5)
                    });
                }
                foreach (string child in ScannerHelpers.EnumerateSubKeyNames(hive, keyPath, view))
                {
                    stack.Push(keyPath + "\\" + child);
                    if (stack.Count + visited > maxKeys) break;
                }
            }
        }

        private static string RegistryValueToSearchText(object value)
        {
            if (value == null) return "";
            if (value is string s) return s;
            if (value is string[] arr) return string.Join(" ", arr);
            if (value is byte[] bytes)
            {
                var sb = new StringBuilder(bytes.Length);
                foreach (byte b in bytes) sb.Append(b >= 32 && b <= 126 ? (char)b : ' ');
                string ascii = sb.ToString();
                string unicode = "";
                try { unicode = Encoding.Unicode.GetString(bytes); } catch { }
                return ascii + " " + unicode;
            }
            return value.ToString() ?? "";
        }

        private static void ScanDefenderHistory(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string root = Path.Combine(programData, @"Microsoft\Windows Defender\Scans\History");
            if (!Directory.Exists(root)) return;
            int count = 0;
            foreach (string file in SafeEnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                if (++count > 20000) break;
                string data = Path.GetFileName(file) + " " + ReadBinaryAsText(file, 1024 * 1024);
                var best = BestRuleMatch(data, rules);
                best = AdjustRuleForEvidenceContext(best, data, "UsageDefenderHistory");
                if (best == null) continue;
                artifacts.Add(new RuntimeArtifact
                {
                    SourceType = "Defender history",
                    Name = Path.GetFileName(file),
                    Path = file,
                    Token = best.Token,
                    Label = best.Label,
                    Details = "Local Windows Defender history/quarantine data matched an indicator token.",
                    When = ScannerHelpers.FileTimeString(file),
                    Severity = best.Severity,
                    Confidence = Math.Min(92, best.Confidence + 2),
                    Score = Math.Max(4, best.Score - 2)
                });
            }
        }

        private static void ScanEventLogTextArtifacts(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            string[] logs =
            {
                "Microsoft-Windows-Windows Defender/Operational",
                "Microsoft-Windows-CodeIntegrity/Operational",
                "Microsoft-Windows-TaskScheduler/Operational",
                "System",
                "Application",
                "Microsoft-Windows-PowerShell/Operational"
            };
            foreach (string log in logs)
            {
                string output = RunCommandCapture("wevtutil qe \"" + log + "\" /rd:true /c:80 /f:text");
                if (string.IsNullOrWhiteSpace(output)) continue;
                int scanned = 0;
                foreach (var rule in rules)
                {
                    if (++scanned > 800) break;
                    int pos = output.IndexOf(rule.Token, StringComparison.OrdinalIgnoreCase);
                    if (pos < 0) continue;
                    string snippet = ScannerHelpers.CollapseWhitespaceForDisplay(Snippet(output, pos, rule.Token.Length));
                    var adjusted = AdjustRuleForEvidenceContext(rule, snippet, "UsageEventLog");
                    if (adjusted == null) continue;
                    artifacts.Add(new RuntimeArtifact
                    {
                        SourceType = "Windows event log",
                        Name = log,
                        Path = log,
                        Token = adjusted.Token,
                        Label = adjusted.Label,
                        Details = snippet,
                        Severity = adjusted.Severity,
                        Confidence = Math.Max(45, adjusted.Confidence - 4),
                        Score = Math.Max(3, adjusted.Score - 4)
                    });
                }
            }
        }

        private static void ScanSrumDatabase(List<RuntimeArtifact> artifacts, List<FileNameRule> rules)
        {
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\sru\SRUDB.dat");
            if (!File.Exists(path)) return;
            string data = ReadBinaryAsText(path, MaxHistoryBytes);
            if (string.IsNullOrWhiteSpace(data)) return;
            foreach (var rule in rules)
            {
                int pos = data.IndexOf(rule.Token, StringComparison.OrdinalIgnoreCase);
                if (pos < 0) continue;
                string snippet = ScannerHelpers.CollapseWhitespaceForDisplay(Snippet(data, pos, rule.Token.Length));
                if (!IsUsefulSrumSnippet(snippet, rule.Token)) continue;
                var adjusted = AdjustRuleForEvidenceContext(rule, snippet, "UsageSrum");
                if (adjusted == null) continue;
                artifacts.Add(new RuntimeArtifact
                {
                    SourceType = "SRUM app activity",
                    Name = rule.Token,
                    Path = path,
                    Token = adjusted.Token,
                    Label = adjusted.Label,
                    Details = snippet,
                    When = ScannerHelpers.FileTimeString(path),
                    Severity = adjusted.Severity,
                    Confidence = Math.Max(45, adjusted.Confidence - 6),
                    Score = Math.Max(3, adjusted.Score - 6)
                });
            }
        }

        private static void ScanCleanupIndicators(ScanReport report)
        {
            var notes = new List<string>();
            try
            {
                string pf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
                if (Directory.Exists(pf))
                {
                    int count = SafeEnumerateFiles(pf, "*.pf", SearchOption.TopDirectoryOnly).Take(250).Count();
                    if (count < 10) notes.Add("Prefetch has very few entries. This can happen naturally, but it can also follow cleanup or disabled tracing.");
                }
            }
            catch { }

            int? enablePrefetcher = ScannerHelpers.ReadRegistryDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters", "EnablePrefetcher");
            if (enablePrefetcher.HasValue && enablePrefetcher.Value == 0) notes.Add("Prefetch is disabled in Windows registry.");

            string defenderRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Scans\History");
            if (Directory.Exists(defenderRoot))
            {
                try
                {
                    DateTime last = Directory.GetLastWriteTime(defenderRoot);
                    if ((DateTime.Now - last).TotalMinutes < 90) notes.Add("Windows Defender history folder changed recently. Review only with other evidence.");
                }
                catch { }
            }

            if (notes.Count > 0)
                report.AddFinding("Cleanup Indicators", "Possible cleanup or missing-trace indicators", string.Join("\n", notes.Select(n => "- " + n)), Severity.Low, 48, Math.Min(20, notes.Count * 6));
            else
                report.AddFinding("Cleanup Indicators", "No obvious cleanup indicators found", "Basic local checks did not find obvious Prefetch/Defender cleanup indicators. Absence of cleanup signals does not prove anything by itself.", Severity.Info, 55, 0);
        }

        private static string Rot13(string input)
        {
            if (string.IsNullOrEmpty(input)) return "";
            var chars = input.ToCharArray();
            for (int i = 0; i < chars.Length; i++)
            {
                char c = chars[i];
                if (c >= 'a' && c <= 'z') chars[i] = (char)('a' + ((c - 'a' + 13) % 26));
                else if (c >= 'A' && c <= 'Z') chars[i] = (char)('A' + ((c - 'A' + 13) % 26));
            }
            return new string(chars);
        }

        private static void DeduplicateRuntimeArtifacts(List<RuntimeArtifact> artifacts)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = artifacts.Count - 1; i >= 0; i--)
            {
                string key = artifacts[i].SourceType + "|" + artifacts[i].Name + "|" + artifacts[i].Path + "|" + artifacts[i].Token;
                if (!seen.Add(key)) artifacts.RemoveAt(i);
            }
        }

        private static List<DriverInfo> CollectDriverInfo(ScanReport report)
        {
            var drivers = new List<DriverInfo>();
            var liveDeviceServices = GetLiveDeviceServiceStateMap();
            foreach (string serviceName in ScannerHelpers.EnumerateSubKeyNames(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services"))
            {
                string sub = @"SYSTEM\CurrentControlSet\Services\" + serviceName;
                int? type = ScannerHelpers.ReadRegistryDword(RegistryHive.LocalMachine, sub, "Type");
                if (!type.HasValue || (type.Value & 0x3) == 0) continue;
                string raw = ScannerHelpers.ReadRegistryString(RegistryHive.LocalMachine, sub, "ImagePath");
                string path = ScannerHelpers.NormalizeServiceBinaryPath(raw);
                string name = string.IsNullOrWhiteSpace(path) ? serviceName : Path.GetFileName(path);
                bool exists = !string.IsNullOrWhiteSpace(path) && File.Exists(path);
                string liveState = "Registry entry";
                string liveDisplayName = "";
                Tuple<string, string> live;
                if (liveDeviceServices.TryGetValue(serviceName, out live))
                {
                    liveState = live.Item1;
                    liveDisplayName = live.Item2;
                }

                var info = new DriverInfo
                {
                    Name = name,
                    RawPath = raw,
                    Path = path,
                    FileExists = exists,
                    WindowsSystemPath = ScannerHelpers.IsWindowsSystemPath(path),
                    Company = exists ? ScannerHelpers.FileCompanyName(path) : "",
                    ProductName = exists ? ScannerHelpers.FileProductName(path) : "",
                    OriginalFileName = exists ? ScannerHelpers.FileOriginalFileName(path) : "",
                    Sha256 = exists ? ScannerHelpers.Sha256File(path) : "",
                    SignedTrusted = exists && ScannerHelpers.HasAuthenticodeSignature(path),
                    SuspiciousNamePattern = IsSuspiciousDriverName(name + " " + serviceName + " " + raw),
                    Service = new DriverServiceInfo
                    {
                        ServiceName = serviceName,
                        DisplayName = string.IsNullOrWhiteSpace(liveDisplayName) ? ScannerHelpers.ReadRegistryString(RegistryHive.LocalMachine, sub, "DisplayName") : liveDisplayName,
                        BinaryPath = path,
                        StartType = ConvertStartType(ScannerHelpers.ReadRegistryDword(RegistryHive.LocalMachine, sub, "Start")),
                        CurrentState = liveState
                    }
                };
                var knownVulnerable = KnownVulnerableDriverCatalog.Evaluate(info);
                if (knownVulnerable != null)
                {
                    info.KnownVulnerableDriver = true;
                    info.KnownVulnerableDriverId = knownVulnerable.RuleId;
                    info.KnownVulnerableDriverName = knownVulnerable.DisplayName;
                    info.KnownVulnerableDriverMatch = knownVulnerable.MatchedBy + ": " + knownVulnerable.MatchedValue;
                    info.KnownVulnerableDriverReason = knownVulnerable.Description;
                    info.KnownVulnerableDriverSeverity = knownVulnerable.Severity;
                    info.KnownVulnerableDriverConfidence = knownVulnerable.Confidence;
                }

                drivers.Add(info);
            }

            var vulnerableDriverMatches = drivers.Where(d => d.KnownVulnerableDriver).OrderByDescending(d => d.KnownVulnerableDriverSeverity).ThenByDescending(d => d.KnownVulnerableDriverConfidence).Take(20).ToList();
            if (vulnerableDriverMatches.Count > 0)
            {
                var sample = string.Join("\n", vulnerableDriverMatches.Select(d => "- " + d.Name + " | " + d.KnownVulnerableDriverName + " | " + d.KnownVulnerableDriverMatch + " | " + d.Path));
                Severity severity = vulnerableDriverMatches.Any(d => d.KnownVulnerableDriverSeverity >= Severity.High) ? Severity.High : Severity.Medium;
                int confidence = Math.Min(92, vulnerableDriverMatches.Max(d => d.KnownVulnerableDriverConfidence));
                int score = Math.Min(70, 18 + vulnerableDriverMatches.Count * 12);
                report.AddFinding("Known Vulnerable Drivers", "Known vulnerable driver indicator(s) found", "Embedded catalog " + KnownVulnerableDriverCatalog.Version + " matched " + vulnerableDriverMatches.Count + " driver record(s). These rows are review context and do not prove cheating by themselves.\n" + sample, severity, confidence, score);
            }

            var suspicious = drivers.Where(d => d.SuspiciousNamePattern).Take(20).ToList();
            if (suspicious.Count > 0)
            {
                var sample = string.Join("\n", suspicious.Select(d => "- " + d.Name + " | " + d.Path));
                report.AddFinding("Drivers", "Suspicious driver/service name patterns", sample, Severity.Medium, 70, Math.Min(80, suspicious.Count * 15));
            }
            report.AddFinding("Drivers", "Driver service inventory captured", "Driver service entries inspected: " + drivers.Count + "; live device services observed: " + liveDeviceServices.Count + "; signed/trusted binaries: " + drivers.Count(d => d.SignedTrusted) + "; missing binaries: " + drivers.Count(d => !d.FileExists) + "; embedded vulnerable-driver catalog: " + KnownVulnerableDriverCatalog.Version + " (" + KnownVulnerableDriverCatalog.RuleCount + " rule families, " + drivers.Count(d => d.KnownVulnerableDriver) + " match(es)).", Severity.Info, 75, 0);
            return drivers;
        }

        private static Dictionary<string, Tuple<string, string>> GetLiveDeviceServiceStateMap()
        {
            var map = new Dictionary<string, Tuple<string, string>>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (ServiceController svc in ServiceController.GetDevices())
                {
                    using (svc)
                    {
                        string name = "";
                        string display = "";
                        string status = "";
                        try { name = svc.ServiceName; display = svc.DisplayName; status = svc.Status.ToString(); } catch { }
                        if (!string.IsNullOrWhiteSpace(name)) map[name] = Tuple.Create(status, display);
                    }
                }
            }
            catch { }
            return map;
        }

        private static string ConvertStartType(int? start)
        {
            switch (start.GetValueOrDefault(-1))
            {
                case 0: return "Boot";
                case 1: return "System";
                case 2: return "Auto";
                case 3: return "Manual";
                case 4: return "Disabled";
                default: return "Unknown";
            }
        }

        private static bool IsSuspiciousDriverName(string value)
        {
            string lower = ScannerHelpers.ToLowerSafe(value);
            return lower.Contains("cheat") || lower.Contains("inject") || lower.Contains("loader") || lower.Contains("mapper") || lower.Contains("spoof") || lower.Contains("hack") || lower.Contains("kdmapper");
        }

        private static void CollectHardwareIdentityInfo(ScanReport report, List<HardwareRecord> records)
        {
            int placeholderCount = 0;
            var placeholderDetails = new StringBuilder();
            var diskSerialCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var macCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int locallyAdministeredPhysicalMacs = 0;

            AddWmiRecords(records, "BaseBoard", "ROOT\\CIMV2", "SELECT Manufacturer,Product,SerialNumber FROM Win32_BaseBoard", "Win32_BaseBoard", ref placeholderCount, placeholderDetails, "Manufacturer", "Product", "SerialNumber");
            AddWmiRecords(records, "BIOS", "ROOT\\CIMV2", "SELECT Manufacturer,SMBIOSBIOSVersion,SerialNumber FROM Win32_BIOS", "Win32_BIOS", ref placeholderCount, placeholderDetails, "Manufacturer", "SMBIOSBIOSVersion", "SerialNumber");
            AddWmiRecords(records, "SystemProduct", "ROOT\\CIMV2", "SELECT Vendor,Name,IdentifyingNumber,UUID FROM Win32_ComputerSystemProduct", "Win32_ComputerSystemProduct", ref placeholderCount, placeholderDetails, "Vendor", "Name", "IdentifyingNumber", "UUID");

            var disks = ScannerHelpers.WmiQueryRows("ROOT\\CIMV2", "SELECT Model,SerialNumber,InterfaceType FROM Win32_DiskDrive", "Model", "SerialNumber", "InterfaceType");
            foreach (var row in disks)
            {
                string model = ScannerHelpers.WmiValue(row, "Model");
                string serial = ScannerHelpers.WmiValue(row, "SerialNumber");
                AddHardwareRecord(records, "DiskDrive", "Model", model, "Win32_DiskDrive");
                AddHardwareRecord(records, "DiskDrive", "SerialNumber", serial, "Win32_DiskDrive");
                if (IsPlaceholderHardwareValue(serial))
                {
                    placeholderCount++;
                    placeholderDetails.AppendLine("Disk serial placeholder/blank for: " + model);
                }
                else
                {
                    diskSerialCounts[serial] = diskSerialCounts.ContainsKey(serial) ? diskSerialCounts[serial] + 1 : 1;
                }
            }

            var nics = ScannerHelpers.WmiQueryRows("ROOT\\CIMV2", "SELECT Description,MACAddress,IPEnabled FROM Win32_NetworkAdapterConfiguration WHERE MACAddress IS NOT NULL", "Description", "MACAddress", "IPEnabled");
            foreach (var row in nics)
            {
                string desc = ScannerHelpers.WmiValue(row, "Description");
                string mac = ScannerHelpers.WmiValue(row, "MACAddress");
                AddHardwareRecord(records, "NetworkAdapter", "Description", desc, "Win32_NetworkAdapterConfiguration");
                AddHardwareRecord(records, "NetworkAdapter", "MACAddress", mac, "Win32_NetworkAdapterConfiguration");
                if (!IsLikelyVirtualOrAuxNetworkAdapter(desc) && !IsPlaceholderHardwareValue(mac))
                {
                    macCounts[mac] = macCounts.ContainsKey(mac) ? macCounts[mac] + 1 : 1;
                    if (IsLocallyAdministeredMac(mac)) locallyAdministeredPhysicalMacs++;
                }
            }

            if (placeholderCount > 0)
            {
                report.AddFinding("Hardware Identity", "Default or missing hardware identifiers", "One or more SMBIOS/hardware identity fields are blank, default, all-zero/all-FF, or OEM placeholder values.\n" + placeholderDetails, Severity.Medium, 70, Math.Min(40, 15 + placeholderCount * 5));
            }
            int duplicateDiskSerials = diskSerialCounts.Count(kv => kv.Value > 1);
            if (duplicateDiskSerials > 0) report.AddFinding("Hardware Identity", "Duplicate disk serial values", duplicateDiskSerials + " duplicate non-placeholder disk serial value(s) were observed.", Severity.Medium, 70, 25);
            int duplicateMacs = macCounts.Count(kv => kv.Value > 1);
            if (duplicateMacs > 0) report.AddFinding("Hardware Identity", "Duplicate physical MAC addresses", duplicateMacs + " duplicate MAC address value(s) were observed on non-virtual network adapters.", Severity.Medium, 75, 25);
            if (locallyAdministeredPhysicalMacs > 0) report.AddFinding("Hardware Identity", "Locally administered physical MAC address observed", locallyAdministeredPhysicalMacs + " non-virtual MAC address value(s) appear locally administered/randomized.", Severity.Low, 60, 8);

            report.AddFinding("Hardware Identity", "Hardware identity records captured", "Hardware identity snapshot collected. Records: " + records.Count + ". Hardware spoofing cannot be proven from one scan without a trusted prior baseline.", Severity.Info, 70, 0);
        }

        private static void AddWmiRecords(List<HardwareRecord> records, string category, string ns, string query, string source, ref int placeholderCount, StringBuilder placeholderDetails, params string[] fields)
        {
            foreach (var row in ScannerHelpers.WmiQueryRows(ns, query, fields))
            {
                foreach (string field in fields)
                {
                    string value = ScannerHelpers.WmiValue(row, field);
                    AddHardwareRecord(records, category, field, value, source);
                    if (field.IndexOf("Serial", StringComparison.OrdinalIgnoreCase) >= 0 || field.Equals("UUID", StringComparison.OrdinalIgnoreCase) || field.Equals("IdentifyingNumber", StringComparison.OrdinalIgnoreCase))
                    {
                        if (IsPlaceholderHardwareValue(value))
                        {
                            placeholderCount++;
                            placeholderDetails.AppendLine(category + " " + field + " = '" + value + "'");
                        }
                    }
                }
            }
        }

        private static void AddHardwareRecord(List<HardwareRecord> records, string category, string name, string value, string source)
        {
            records.Add(new HardwareRecord { Category = category, Name = name, Value = value ?? "", Source = source });
        }

        private static bool IsPlaceholderHardwareValue(string raw)
        {
            string v = ScannerHelpers.ToLowerSafe(ScannerHelpers.Trim(raw));
            if (string.IsNullOrWhiteSpace(v)) return true;
            string[] placeholders = { "to be filled by o.e.m", "to be filled by oem", "default string", "system serial number", "base board serial number", "none", "unknown", "not specified", "not available", "n/a", "na", "o.e.m", "oem", "null", "invalid", "empty", "123456789", "0123456789", "serialnumber", "serial number" };
            if (placeholders.Any(p => v == p || v.Contains(p))) return true;
            string compact = Regex.Replace(v, "[^a-z0-9]", "");
            if (compact.Length >= 6 && compact.All(c => c == compact[0])) return true;
            return v == "00000000-0000-0000-0000-000000000000" || v == "ffffffff-ffff-ffff-ffff-ffffffffffff";
        }

        private static bool IsLikelyVirtualOrAuxNetworkAdapter(string description)
        {
            string d = ScannerHelpers.ToLowerSafe(description);
            string[] tokens = { "virtual", "vpn", "bluetooth", "loopback", "hyper-v", "vmware", "virtualbox", "tap", "tun", "wan miniport", "npcap", "docker", "wsl" };
            return tokens.Any(t => d.Contains(t));
        }

        private static bool IsLocallyAdministeredMac(string mac)
        {
            string hex = Regex.Replace(mac ?? "", "[^0-9a-fA-F]", "");
            if (hex.Length < 2) return false;
            int first;
            return int.TryParse(hex.Substring(0, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out first) && (first & 0x02) != 0;
        }

        private static void CollectExternalDeviceInfo(ScanReport report, List<DeviceConnectionRecord> records)
        {
            AddUsbRegistryRecords(records, "USB", false);
            AddUsbRegistryRecords(records, "USBSTOR", true);

            var present = ScannerHelpers.WmiQueryRows("ROOT\\CIMV2", "SELECT Name,Manufacturer,PNPDeviceID,Service,ClassGuid FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%'", "Name", "Manufacturer", "PNPDeviceID", "Service", "ClassGuid");
            var presentIds = new HashSet<string>(present.Select(r => ScannerHelpers.WmiValue(r, "PNPDeviceID")), StringComparer.OrdinalIgnoreCase);
            foreach (var rec in records) if (presentIds.Contains(rec.DeviceId)) rec.CurrentlyPresent = true;

            if (records.Count > 0)
                report.AddFinding("External Devices", "External USB device history captured", "USB/USBSTOR registry records captured: " + records.Count + "; records with install/arrival/removal timestamps: " + records.Count(r => !string.IsNullOrWhiteSpace(r.FirstInstallTime) || !string.IsNullOrWhiteSpace(r.InstallTime) || !string.IsNullOrWhiteSpace(r.LastArrivalTime) || !string.IsNullOrWhiteSpace(r.LastRemovalTime)) + "; currently present: " + records.Count(r => r.CurrentlyPresent) + ".", Severity.Info, 75, 0);
            else
                report.AddFinding("External Devices", "No retained USB device history found", "USB/USBSTOR registry records were not available or could not be read.", Severity.Info, 50, 0);
        }

        private static void AddUsbRegistryRecords(List<DeviceConnectionRecord> records, string enumName, bool massStorage)
        {
            string root = @"SYSTEM\CurrentControlSet\Enum\" + enumName;
            foreach (string device in ScannerHelpers.EnumerateSubKeyNames(RegistryHive.LocalMachine, root).Take(2000))
            {
                foreach (string instance in ScannerHelpers.EnumerateSubKeyNames(RegistryHive.LocalMachine, root + "\\" + device).Take(2000))
                {
                    string sub = root + "\\" + device + "\\" + instance;
                    var values = ScannerHelpers.ReadRegistryValues(RegistryHive.LocalMachine, sub);
                    string desc = Value(values, "FriendlyName");
                    if (string.IsNullOrWhiteSpace(desc)) desc = Value(values, "DeviceDesc");
                    string keyLastWrite = ScannerHelpers.RegistryKeyLastWriteTime(RegistryHive.LocalMachine, sub);
                    string firstInstall = ReadDevicePropertyTimestamp(sub, "0065");
                    string install = ReadDevicePropertyTimestamp(sub, "0064");
                    string lastArrival = ReadDevicePropertyTimestamp(sub, "0066");
                    string lastRemoval = ReadDevicePropertyTimestamp(sub, "0067");
                    if (string.IsNullOrWhiteSpace(install)) install = keyLastWrite;

                    records.Add(new DeviceConnectionRecord
                    {
                        Enumerator = enumName,
                        DeviceId = enumName + "\\" + device + "\\" + instance,
                        Description = desc,
                        Manufacturer = Value(values, "Mfg"),
                        Service = Value(values, "Service"),
                        ClassName = Value(values, "Class"),
                        Location = Value(values, "LocationInformation"),
                        FirstInstallTime = firstInstall,
                        InstallTime = install,
                        LastArrivalTime = lastArrival,
                        LastRemovalTime = lastRemoval,
                        CurrentlyPresent = false,
                        MassStorage = massStorage,
                        Source = string.IsNullOrWhiteSpace(keyLastWrite) ? "Registry Enum\\" + enumName : "Registry Enum\\" + enumName + " (key last write fallback captured)"
                    });
                }
            }
        }

        private static string ReadDevicePropertyTimestamp(string deviceInstanceSubKey, string propertyIdHex)
        {
            const string devicePropertySet = @"Properties\{83da6326-97a6-4088-9453-a1923f573b29}";
            string subkey = deviceInstanceSubKey + "\\" + devicePropertySet + "\\" + propertyIdHex;
            var values = ScannerHelpers.ReadRegistryValues(RegistryHive.LocalMachine, subkey);
            foreach (var value in values.Values)
            {
                string ts = ScannerHelpers.RegistryFileTimeValueToString(value);
                if (!string.IsNullOrWhiteSpace(ts)) return ts;
            }
            object defaultValue = ScannerHelpers.ReadRegistryValue(RegistryHive.LocalMachine, subkey, "");
            return ScannerHelpers.RegistryFileTimeValueToString(defaultValue);
        }



        private static void CollectDmaPcieDeviceInfo(ScanReport report, List<DmaDeviceRecord> records)
        {
            if (records == null) return;

            AddDmaPcieRegistryRecords(records, "PCI", 650);
            AddDmaPcieRegistryRecords(records, "USB4", 120);
            AddDmaPciePresentWmiRecords(records);
            AddSetupApiDmaPcieRecords(records, 160);
            DeduplicateDmaPcieRecords(records);

            int timestamped = records.Count(r => !string.IsNullOrWhiteSpace(r.FirstInstallTime) || !string.IsNullOrWhiteSpace(r.InstallTime) || !string.IsNullOrWhiteSpace(r.LastArrivalTime) || !string.IsNullOrWhiteSpace(r.LastRemovalTime));
            int present = records.Count(r => r.CurrentlyPresent);
            int identityReview = records.Count(r => r.Severity == Severity.Low);
            int priorityReview = records.Count(r => r.Severity >= Severity.Medium);
            int externalHotplug = records.Count(r => ContainsAnyInsensitive(r.ReviewReason, "Thunderbolt", "USB4", "CFexpress", "ExpressCard"));
            int fpgaOrDma = records.Count(r => ContainsAnyInsensitive(r.Name + " " + r.Manufacturer + " " + r.DeviceId + " " + r.ReviewReason, "DMA", "FPGA", "PCILeech", "LeechCore", "Screamer", "Xilinx", "Altera", "Lattice", "Artix", "Kintex", "Spartan"));

            if (records.Count == 0)
            {
                report.AddFinding("DMA / PCIe Review", "No DMA / PCIe device records captured", "Windows did not return PCI/PCIe, Thunderbolt, USB4, CFexpress, or setup-log device records from the local scan sources. This does not prove that DMA hardware was never attached.", Severity.Info, 45, 0);
                return;
            }

            var topReview = records
                .Where(r => r.Severity >= Severity.Medium)
                .OrderByDescending(r => r.Severity)
                .ThenByDescending(r => r.Confidence)
                .Take(10)
                .Select(r => "- " + DmaPcieDisplayName(r) + " | " + r.ReviewReason)
                .ToList();

            string details = "DMA / PCIe hardware context captured for reviewer use. Records captured: " + records.Count + "; present records: " + present + "; limited-identity PCI records: " + identityReview + "; priority review: " + priorityReview + "; external hot-plug paths: " + externalHotplug + "; DMA/FPGA-like terms: " + fpgaOrDma + ".";
            if (priorityReview == 0) details += " No priority DMA-style hardware indicators found. This section is context only and does not prove cheating without matching browser, file, driver, execution, or runtime evidence.";
            else details += " Priority review rows are listed below; treat them as context unless corroborated by browser, file, driver, execution, or runtime evidence.\n" + string.Join("\n", topReview);

            Severity severity = priorityReview > 0 ? Severity.Medium : (identityReview > 0 ? Severity.Low : Severity.Info);
            int confidence = priorityReview > 0 ? 72 : (identityReview > 0 ? 62 : 55);
            int score = priorityReview > 0 ? Math.Min(24, 8 + priorityReview * 4 + fpgaOrDma * 4 + externalHotplug * 2) : 0;
            report.AddFinding("DMA / PCIe Review", priorityReview > 0 ? "DMA-capable hardware needs review" : "DMA / PCIe hardware context captured", details, severity, confidence, score);
        }

        private static void AddDmaPcieRegistryRecords(List<DmaDeviceRecord> records, string enumName, int limit)
        {
            string root = @"SYSTEM\CurrentControlSet\Enum\" + enumName;
            int added = 0;
            foreach (string device in ScannerHelpers.EnumerateSubKeyNames(RegistryHive.LocalMachine, root).Take(limit))
            {
                foreach (string instance in ScannerHelpers.EnumerateSubKeyNames(RegistryHive.LocalMachine, root + "\\" + device).Take(100))
                {
                    if (added >= limit) return;
                    string sub = root + "\\" + device + "\\" + instance;
                    var values = ScannerHelpers.ReadRegistryValues(RegistryHive.LocalMachine, sub);
                    string rawDesc = FirstNonBlank(Value(values, "FriendlyName"), Value(values, "DeviceDesc"), device);
                    string desc = NormalizeDmaPcieDeviceName(rawDesc, device);
                    string manufacturer = NormalizeDmaPcieDeviceName(Value(values, "Mfg"), "");
                    string service = Value(values, "Service");
                    string className = Value(values, "Class");
                    string classGuid = Value(values, "ClassGUID");
                    string location = Value(values, "LocationInformation");
                    if (!string.IsNullOrWhiteSpace(rawDesc) && !string.Equals(rawDesc, desc, StringComparison.OrdinalIgnoreCase)) location = JoinNonBlankDistinct(location, "Raw registry name: " + rawDesc);
                    string hardwareIds = RegistryValueToDisplay(values, "HardwareID");
                    string compatibleIds = RegistryValueToDisplay(values, "CompatibleIDs");
                    string deviceId = enumName + "\\" + device + "\\" + instance;
                    string reviewReason = BuildDmaPcieReviewReason(enumName, deviceId, desc, manufacturer, service, className, classGuid, location, hardwareIds, compatibleIds);
                    Severity severity = DmaPcieReviewSeverity(reviewReason);
                    int confidence = DmaPcieReviewConfidence(reviewReason, severity);
                    string keyLastWrite = ScannerHelpers.RegistryKeyLastWriteTime(RegistryHive.LocalMachine, sub);
                    string firstInstall = ReadDevicePropertyTimestamp(sub, "0065");
                    string install = ReadDevicePropertyTimestamp(sub, "0064");
                    string lastArrival = ReadDevicePropertyTimestamp(sub, "0066");
                    string lastRemoval = ReadDevicePropertyTimestamp(sub, "0067");
                    if (string.IsNullOrWhiteSpace(install)) install = keyLastWrite;

                    records.Add(new DmaDeviceRecord
                    {
                        Enumerator = enumName,
                        DeviceId = deviceId,
                        Name = desc,
                        Manufacturer = manufacturer,
                        Service = service,
                        ClassName = className,
                        ClassGuid = classGuid,
                        Location = location,
                        HardwareIds = hardwareIds,
                        CompatibleIds = compatibleIds,
                        FirstInstallTime = firstInstall,
                        InstallTime = install,
                        LastArrivalTime = lastArrival,
                        LastRemovalTime = lastRemoval,
                        CurrentlyPresent = false,
                        Source = string.IsNullOrWhiteSpace(keyLastWrite) ? "Registry Enum\\" + enumName : "Registry Enum\\" + enumName + " (key last write fallback captured)",
                        ReviewReason = reviewReason,
                        Severity = severity,
                        Confidence = confidence
                    });
                    added++;
                }
            }
        }

        private static void AddDmaPciePresentWmiRecords(List<DmaDeviceRecord> records)
        {
            var rows = ScannerHelpers.WmiQueryRows("ROOT\\CIMV2", "SELECT Name,Description,Manufacturer,PNPDeviceID,Service,ClassGuid,PNPClass,Status FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'PCI%' OR PNPDeviceID LIKE 'USB4%' OR Name LIKE '%Thunderbolt%' OR Name LIKE '%USB4%' OR Description LIKE '%Thunderbolt%' OR Description LIKE '%USB4%' OR Description LIKE '%CFexpress%'", "Name", "Description", "Manufacturer", "PNPDeviceID", "Service", "ClassGuid", "PNPClass", "Status");
            foreach (var row in rows.Take(750))
            {
                string deviceId = ScannerHelpers.WmiValue(row, "PNPDeviceID");
                if (string.IsNullOrWhiteSpace(deviceId)) continue;
                string name = NormalizeDmaPcieDeviceName(FirstNonBlank(ScannerHelpers.WmiValue(row, "Name"), ScannerHelpers.WmiValue(row, "Description"), deviceId), deviceId);
                string manufacturer = NormalizeDmaPcieDeviceName(ScannerHelpers.WmiValue(row, "Manufacturer"), "");
                string service = ScannerHelpers.WmiValue(row, "Service");
                string classGuid = ScannerHelpers.WmiValue(row, "ClassGuid");
                string className = ScannerHelpers.WmiValue(row, "PNPClass");
                string status = ScannerHelpers.WmiValue(row, "Status");
                string reviewReason = BuildDmaPcieReviewReason(GetEnumeratorFromDeviceId(deviceId), deviceId, name, manufacturer, service, className, classGuid, "Status=" + status, "", "");
                Severity severity = DmaPcieReviewSeverity(reviewReason);

                records.Add(new DmaDeviceRecord
                {
                    Enumerator = GetEnumeratorFromDeviceId(deviceId),
                    DeviceId = deviceId,
                    Name = name,
                    Manufacturer = manufacturer,
                    Service = service,
                    ClassName = className,
                    ClassGuid = classGuid,
                    Location = "Status: " + status,
                    CurrentlyPresent = true,
                    Source = "Win32_PnPEntity live inventory",
                    ReviewReason = reviewReason,
                    Severity = severity,
                    Confidence = DmaPcieReviewConfidence(reviewReason, severity)
                });
            }
        }

        private static void AddSetupApiDmaPcieRecords(List<DmaDeviceRecord> records, int limit)
        {
            try
            {
                string path = Path.Combine(ScannerHelpers.GetWindowsDirectoryPath(), "INF", "setupapi.dev.log");
                if (!File.Exists(path)) return;

                string text = ReadTailText(path, 8 * 1024 * 1024);
                if (string.IsNullOrWhiteSpace(text)) return;

                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                string currentSectionTime = "";
                using (var reader = new StringReader(text))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null && seen.Count < limit)
                    {
                        var section = Regex.Match(line, @"Section start\s+([0-9]{4}/[0-9]{2}/[0-9]{2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2})", RegexOptions.IgnoreCase);
                        if (section.Success) currentSectionTime = NormalizeSetupApiTimestamp(section.Groups[1].Value);

                        var match = Regex.Match(line, @"(?i)(PCI\\VEN_[A-Z0-9&_.\\-]+|USB4\\[A-Z0-9&_.\\-]+)");
                        if (!match.Success && !ContainsAnyInsensitive(line, "Thunderbolt", "USB4", "CFexpress", "PCILeech", "LeechCore", "Screamer", "FPGA", "Xilinx", "Altera", "Lattice")) continue;

                        string deviceId = match.Success ? match.Groups[1].Value.Trim() : ShortLogDeviceEvidence(line);
                        if (string.IsNullOrWhiteSpace(deviceId) || !seen.Add(deviceId)) continue;

                        string reviewReason = BuildDmaPcieReviewReason(GetEnumeratorFromDeviceId(deviceId), deviceId, line, "", "", "", "", "", "", "") + "; historical SetupAPI install/log evidence";
                        Severity severity = DmaPcieReviewSeverity(reviewReason);
                        records.Add(new DmaDeviceRecord
                        {
                            Enumerator = FirstNonBlank(GetEnumeratorFromDeviceId(deviceId), "SetupAPI"),
                            DeviceId = deviceId,
                            Name = ShortLogDeviceEvidence(line),
                            InstallTime = currentSectionTime,
                            Source = "SetupAPI.dev.log",
                            ReviewReason = reviewReason,
                            Severity = severity,
                            Confidence = Math.Max(45, DmaPcieReviewConfidence(reviewReason, severity) - 10)
                        });
                    }
                }
            }
            catch { }
        }

        private static void DeduplicateDmaPcieRecords(List<DmaDeviceRecord> records)
        {
            var best = new Dictionary<string, DmaDeviceRecord>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in records.ToList())
            {
                string key = string.IsNullOrWhiteSpace(r.DeviceId) ? (r.Source + "|" + r.Name) : NormalizeDeviceInstanceId(r.DeviceId);
                DmaDeviceRecord existing;
                if (!best.TryGetValue(key, out existing))
                {
                    best[key] = r;
                    continue;
                }
                MergeDmaPcieRecord(existing, r);
            }

            records.Clear();
            records.AddRange(best.Values
                .OrderByDescending(r => r.Severity)
                .ThenByDescending(r => r.Confidence)
                .ThenByDescending(r => r.CurrentlyPresent)
                .ThenBy(r => r.Name)
                .Take(900));
        }

        private static void MergeDmaPcieRecord(DmaDeviceRecord target, DmaDeviceRecord source)
        {
            target.Name = FirstNonBlank(target.Name, source.Name);
            target.Manufacturer = FirstNonBlank(target.Manufacturer, source.Manufacturer);
            target.Service = FirstNonBlank(target.Service, source.Service);
            target.ClassName = FirstNonBlank(target.ClassName, source.ClassName);
            target.ClassGuid = FirstNonBlank(target.ClassGuid, source.ClassGuid);
            target.Location = JoinNonBlankDistinct(target.Location, source.Location);
            target.HardwareIds = JoinNonBlankDistinct(target.HardwareIds, source.HardwareIds);
            target.CompatibleIds = JoinNonBlankDistinct(target.CompatibleIds, source.CompatibleIds);
            target.FirstInstallTime = FirstNonBlank(target.FirstInstallTime, source.FirstInstallTime);
            target.InstallTime = FirstNonBlank(target.InstallTime, source.InstallTime);
            target.LastArrivalTime = FirstNonBlank(target.LastArrivalTime, source.LastArrivalTime);
            target.LastRemovalTime = FirstNonBlank(target.LastRemovalTime, source.LastRemovalTime);
            target.CurrentlyPresent = target.CurrentlyPresent || source.CurrentlyPresent;
            target.Source = JoinNonBlankDistinct(target.Source, source.Source);
            target.ReviewReason = JoinReasonFragmentsDistinct(target.ReviewReason, source.ReviewReason);
            if (source.Severity > target.Severity) target.Severity = source.Severity;
            target.Confidence = Math.Max(target.Confidence, source.Confidence);
        }

        private static string BuildDmaPcieReviewReason(string enumerator, string deviceId, string name, string manufacturer, string service, string className, string classGuid, string location, string hardwareIds, string compatibleIds)
        {
            string combined = ScannerHelpers.ToLowerSafe(string.Join(" ", new[] { enumerator, deviceId, name, manufacturer, service, className, classGuid, location, hardwareIds, compatibleIds }));
            var reasons = new List<string>();

            if (combined.Contains("thunderbolt")) reasons.Add("Thunderbolt device path can expose external PCIe/DMA-capable hardware");
            if (combined.Contains("usb4")) reasons.Add("USB4 device path can expose external PCIe/DMA-capable hardware");
            if (combined.Contains("cfexpress") || combined.Contains("expresscard")) reasons.Add("External PCIe-style expansion/storage path");
            if (combined.Contains("fpga") || combined.Contains("xilinx") || combined.Contains("altera") || combined.Contains("lattice") || combined.Contains("artix") || combined.Contains("kintex") || combined.Contains("spartan")) reasons.Add("FPGA/DMA-adjacent hardware term");
            if (combined.Contains("pcileech") || combined.Contains("leechcore") || combined.Contains("screamer") || combined.Contains("dma")) reasons.Add("Direct DMA tooling or DMA keyword");
            if (combined.Contains("unknown device") || combined.Contains("base system device") || combined.Contains("pci device") || combined.Contains("multimedia controller") || string.IsNullOrWhiteSpace(name)) reasons.Add("Generic or unknown PCI device identity");
            if (combined.Contains("ven_") && combined.Contains("dev_") && (string.IsNullOrWhiteSpace(manufacturer) || manufacturer.Equals("Unknown", StringComparison.OrdinalIgnoreCase))) reasons.Add("PCI vendor/device ID present with limited manufacturer identity");
            if (ScannerHelpers.StartsWithInsensitive(deviceId, "PCI\\")) reasons.Add("PCI/PCIe device retained by Windows; review only if unexpected");
            if (ScannerHelpers.StartsWithInsensitive(deviceId, "USB4\\")) reasons.Add("USB4 device retained by Windows; review external-device context");

            if (reasons.Count == 0) reasons.Add("DMA-capable device context captured for baseline review only");
            return string.Join("; ", reasons.Distinct(StringComparer.OrdinalIgnoreCase));
        }

        private static Severity DmaPcieReviewSeverity(string reason)
        {
            string r = ScannerHelpers.ToLowerSafe(reason);
            if (ContainsAnyInsensitive(r, "direct dma", "pcileech", "leechcore", "screamer", "fpga", "xilinx", "altera", "lattice", "artix", "kintex", "spartan")) return Severity.Medium;
            if (ContainsAnyInsensitive(r, "thunderbolt", "usb4", "cfexpress", "expresscard", "unknown pci", "generic or unknown", "limited manufacturer")) return Severity.Low;
            return Severity.Info;
        }

        private static int DmaPcieReviewConfidence(string reason, Severity severity)
        {
            int confidence = severity == Severity.Medium ? 72 : (severity == Severity.Low ? 60 : 45);
            if (ContainsAnyInsensitive(reason, "historical SetupAPI")) confidence = Math.Max(40, confidence - 8);
            return confidence;
        }

        private static string DmaPcieDisplayName(DmaDeviceRecord record)
        {
            if (record == null) return "PCI/PCIe device";
            string name = NormalizeDmaPcieDeviceName(record.Name, record.DeviceId);
            if (string.IsNullOrWhiteSpace(name) || LooksLikeSetupApiDeviceLine(name)) name = FirstNonBlank(record.DeviceId, record.Name, "PCI/PCIe device");
            return name;
        }

        private static bool LooksLikeSetupApiDeviceLine(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            return v.StartsWith("dvi:") || v.StartsWith("ndv:") || v.StartsWith("inf:") || v.Contains(" pci\\ven_") || v.Contains("usb4\\");
        }

        private static string NormalizeDmaPcieDeviceName(string value, string fallback)
        {
            string clean = ScannerHelpers.CollapseWhitespaceForDisplay(value ?? "").Trim();
            if (string.IsNullOrWhiteSpace(clean)) return ScannerHelpers.Trim(fallback);

            int semi = clean.LastIndexOf(';');
            if (semi >= 0 && semi < clean.Length - 1)
            {
                string after = clean.Substring(semi + 1).Trim();
                if (!string.IsNullOrWhiteSpace(after) && !after.StartsWith("%", StringComparison.Ordinal)) return after;
            }

            var quoted = Regex.Match(clean, @"^@[^,]+,%[^%]+%;(.+)$", RegexOptions.IgnoreCase);
            if (quoted.Success && !string.IsNullOrWhiteSpace(quoted.Groups[1].Value)) return quoted.Groups[1].Value.Trim();

            if (clean.StartsWith("@", StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(fallback)) return ScannerHelpers.Trim(fallback);
            return clean;
        }

        private static string JoinReasonFragmentsDistinct(params string[] values)
        {
            var fragments = new List<string>();
            foreach (string value in values ?? new string[0])
            {
                if (string.IsNullOrWhiteSpace(value)) continue;
                foreach (string part in value.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string clean = ScannerHelpers.CollapseWhitespaceForDisplay(part).Trim();
                    if (!string.IsNullOrWhiteSpace(clean)) fragments.Add(clean);
                }
            }
            return string.Join("; ", fragments.Distinct(StringComparer.OrdinalIgnoreCase));
        }

        private static string RegistryValueToDisplay(Dictionary<string, object> values, string key)
        {
            object v;
            if (values == null || !values.TryGetValue(key, out v) || v == null) return "";
            if (v is string[] strings) return string.Join(", ", strings.Where(x => !string.IsNullOrWhiteSpace(x)).Take(12));
            if (v is object[] objects) return string.Join(", ", objects.Select(o => o == null ? "" : o.ToString()).Where(x => !string.IsNullOrWhiteSpace(x)).Take(12));
            return ScannerHelpers.Trim(v.ToString());
        }

        private static string ReadTailText(string path, int maxBytes)
        {
            try
            {
                var info = new FileInfo(path);
                int count = (int)Math.Min(info.Length, Math.Max(4096, maxBytes));
                long start = Math.Max(0, info.Length - count);
                byte[] bytes = new byte[count];
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    fs.Seek(start, SeekOrigin.Begin);
                    int read = fs.Read(bytes, 0, bytes.Length);
                    if (read < bytes.Length) Array.Resize(ref bytes, read);
                }

                int sample = Math.Min(bytes.Length, 4096);
                int zerosOdd = 0;
                int zerosEven = 0;
                for (int i = 0; i < sample; i++)
                {
                    if (bytes[i] == 0)
                    {
                        if ((i & 1) == 0) zerosEven++;
                        else zerosOdd++;
                    }
                }

                Encoding encoding = (zerosOdd > sample / 6 || zerosEven > sample / 6) ? Encoding.Unicode : Encoding.UTF8;
                return encoding.GetString(bytes);
            }
            catch { return ""; }
        }

        private static string NormalizeSetupApiTimestamp(string value)
        {
            DateTime dt;
            if (DateTime.TryParseExact(value, "yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out dt))
                return dt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            return ScannerHelpers.Trim(value);
        }

        private static string ShortLogDeviceEvidence(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return "";
            string clean = Regex.Replace(line, "\\s+", " ").Trim();
            return clean.Length <= 220 ? clean : clean.Substring(0, 220);
        }

        private static string GetEnumeratorFromDeviceId(string deviceId)
        {
            if (string.IsNullOrWhiteSpace(deviceId)) return "";
            int slash = deviceId.IndexOf('\\');
            return slash > 0 ? deviceId.Substring(0, slash) : "";
        }

        private static string NormalizeDeviceInstanceId(string deviceId)
        {
            return Regex.Replace(deviceId ?? "", "\\s+", "").Trim().ToUpperInvariant();
        }

        private static bool ContainsAnyInsensitive(string value, params string[] tokens)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            return tokens.Any(t => !string.IsNullOrWhiteSpace(t) && v.Contains(ScannerHelpers.ToLowerSafe(t)));
        }

        private static string FirstNonBlank(params string[] values)
        {
            foreach (string v in values)
            {
                if (!string.IsNullOrWhiteSpace(v)) return v;
            }
            return "";
        }

        private static string JoinNonBlankDistinct(params string[] values)
        {
            return string.Join("; ", (values ?? new string[0]).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).Distinct(StringComparer.OrdinalIgnoreCase));
        }

        private static void AddScanLimitationsSummary(ScanReport report)
        {
            if (report == null || report.Limitations.Count == 0) return;
            var grouped = report.Limitations
                .GroupBy(l => string.IsNullOrWhiteSpace(l.Source) ? "Unknown" : l.Source)
                .Select(g => g.Key + ": " + g.Count())
                .Take(8);
            string sample = string.Join("\n", report.Limitations.Take(12).Select(l => "- " + (string.IsNullOrWhiteSpace(l.Source) ? "Scan" : l.Source) + " / " + (string.IsNullOrWhiteSpace(l.Scope) ? "General" : l.Scope) + ": " + l.Message + (string.IsNullOrWhiteSpace(l.Path) ? "" : " | " + l.Path)));
            string details = "Some data sources could not be fully read. This does not mean evidence was found; it means the reviewer should understand what was incomplete. Groups: " + string.Join(", ", grouped) + ".\n" + sample;
            report.AddFinding("Scan Limitations", "Some scan sources were incomplete", details, Severity.Low, 70, 0);
        }

        private static List<SourceProjectSummary> AnalyzeSourceProjects(ScanReport report, List<FileNameMatch> fileMatches, List<ExecutionArtifact> executionArtifacts, List<RuntimeArtifact> runtimeArtifacts)
        {
            var map = new Dictionary<string, SourceProjectSummary>(StringComparer.OrdinalIgnoreCase);
            foreach (var match in fileMatches)
            {
                if (!IsDirectCheatSourceMatch(match) && !LooksLikeProjectOrBuildArtifact(match.Path)) continue;
                string root = GuessProjectRoot(match.Path);
                SourceProjectSummary summary;
                if (!map.TryGetValue(root, out summary))
                {
                    summary = new SourceProjectSummary { Root = root };
                    map[root] = summary;
                }
                summary.TotalDetections++;
                if (IsDirectCheatSourceMatch(match)) summary.DirectSourceCount++;
                if (Regex.IsMatch(match.Path, "\\.(sln|vcxproj|csproj|filters|props|targets|h|hpp|cpp|cxx|cs)$", RegexOptions.IgnoreCase)) summary.ProjectFileCount++;
                if (Regex.IsMatch(match.Path, @"\\(bin|obj|x64|x86|release|debug)\\", RegexOptions.IgnoreCase)) summary.BuildArtifactCount++;
                if (ScannerHelpers.ContainsInsensitive(match.Token, "mapper") || ScannerHelpers.ContainsInsensitive(match.Token, "kdmapper")) summary.MapperCount++;
                if (ScannerHelpers.ContainsInsensitive(match.Token, "inject") || ScannerHelpers.ContainsInsensitive(match.Token, "spoofer")) summary.InjectorSpooferTraceCount++;
                summary.MaxConfidence = Math.Max(summary.MaxConfidence, match.Confidence);
                summary.MaxScore = Math.Max(summary.MaxScore, match.Score);
                if (match.Severity > summary.MaxSeverity) summary.MaxSeverity = match.Severity;
                summary.Tokens.Add(match.Token);
                summary.Labels.Add(match.Label);
                if (summary.Samples.Count < 12) summary.Samples.Add(match.Path);
            }

            foreach (var artifact in executionArtifacts) AddArtifactToSourceProjectMap(map, artifact.Path, artifact.Token, artifact.Label, artifact.Severity, artifact.Confidence, artifact.Score);
            foreach (var artifact in runtimeArtifacts) AddArtifactToSourceProjectMap(map, artifact.Path, artifact.Token, artifact.Label, artifact.Severity, artifact.Confidence, artifact.Score);

            foreach (var s in map.Values)
            {
                s.GeneratedStructure = s.ProjectFileCount > 0 || s.BuildArtifactCount > 0;
                s.Determination = s.DirectSourceCount > 0 && s.GeneratedStructure
                    ? "Strong source/build structure indicator"
                    : s.DirectSourceCount > 0 ? "Direct cheat/source naming indicator" : "Project/build context indicator";
            }
            var projects = map.Values.Where(IsMeaningfulSourceProjectGroup).OrderByDescending(s => s.MaxScore).ThenByDescending(s => s.TotalDetections).ToList();
            if (projects.Count > 0)
            {
                var sample = string.Join("\n", projects.Take(8).Select(p => "- " + p.Determination + ": " + p.Root + " (direct: " + p.DirectSourceCount + ", supporting: " + Math.Max(0, p.TotalDetections - p.DirectSourceCount) + ")"));
                report.AddFinding("Source Projects", "Cheat software/source/build evidence grouped", sample, projects.Max(p => p.MaxSeverity), Math.Min(95, projects.Max(p => p.MaxConfidence)), Math.Min(130, projects.Sum(p => p.MaxScore + p.DirectSourceCount * 6 + Math.Min(12, Math.Max(0, p.TotalDetections - p.DirectSourceCount)))));
            }
            else report.AddFinding("Source Projects", "No source/build project groups found", "No grouped source/build structures were identified from the scoped file scan.", Severity.Info, 55, 0);
            return projects;
        }

        private static void AddArtifactToSourceProjectMap(Dictionary<string, SourceProjectSummary> map, string path, string token, string label, Severity severity, int confidence, int score)
        {
            if (string.IsNullOrWhiteSpace(path) || !LooksLikeProjectOrBuildArtifact(path)) return;
            string root = GuessProjectRoot(path);
            SourceProjectSummary summary;
            if (!map.TryGetValue(root, out summary))
            {
                summary = new SourceProjectSummary { Root = root };
                map[root] = summary;
            }
            summary.TotalDetections++;
            if (Regex.IsMatch(path, "\\.(sln|vcxproj|csproj|filters|props|targets|h|hpp|cpp|cxx|cs)$", RegexOptions.IgnoreCase)) summary.ProjectFileCount++;
            if (Regex.IsMatch(path, @"\\(bin|obj|x64|x86|release|debug)\\", RegexOptions.IgnoreCase)) summary.BuildArtifactCount++;
            if (ScannerHelpers.ContainsInsensitive(token, "mapper") || ScannerHelpers.ContainsInsensitive(token, "kdmapper")) summary.MapperCount++;
            if (ScannerHelpers.ContainsInsensitive(token, "inject") || ScannerHelpers.ContainsInsensitive(token, "spoofer")) summary.InjectorSpooferTraceCount++;
            summary.MaxConfidence = Math.Max(summary.MaxConfidence, confidence);
            summary.MaxScore = Math.Max(summary.MaxScore, score);
            if (severity > summary.MaxSeverity) summary.MaxSeverity = severity;
            if (!string.IsNullOrWhiteSpace(token)) summary.Tokens.Add(token);
            if (!string.IsNullOrWhiteSpace(label)) summary.Labels.Add(label);
            if (summary.Samples.Count < 12) summary.Samples.Add(path);
        }

        private static bool IsDirectCheatSourceMatch(FileNameMatch m)
        {
            string token = ScannerHelpers.ToLowerSafe(m.Token);
            string path = ScannerHelpers.ToLowerSafe(m.Path);
            string combined = ScannerHelpers.ToLowerSafe(m.Token + " " + m.Label + " " + m.Path);

            if (IsCommonDependencyOrGeneratedPath(path) && IsGenericProjectStructureToken(token)) return false;
            if (IsGenericProjectStructureToken(token)) return false;

            if (IsStrongDirectCheatFileToken(token)) return true;
            if (combined.Contains("extreme injector") || combined.Contains("kdmapper") || combined.Contains("driver mapper") || combined.Contains("hwid spoofer")) return true;
            if (combined.Contains("aimbot") || combined.Contains("triggerbot") || combined.Contains("wallhack") || combined.Contains("radar") || combined.Contains("chams") || combined.Contains("rcs")) return true;
            if (combined.Contains("cheat source") || combined.Contains("cheat project") || combined.Contains("cheat build")) return true;
            return false;
        }

        private static bool LooksLikeProjectOrBuildArtifact(string path)
        {
            string value = path ?? "";
            if (IsCommonDependencyOrGeneratedPath(value) && !ContainsStrongCheatContext(value)) return false;
            return Regex.IsMatch(value, "\\.(sln|vcxproj|csproj|h|hpp|cpp|cxx|cs|pdb|lib|dll|sys|exe)$", RegexOptions.IgnoreCase)
                || Regex.IsMatch(value, @"\\(bin|obj|x64|x86|release|debug|build)\\", RegexOptions.IgnoreCase)
                || (Regex.IsMatch(value, @"\\(src|source)\\", RegexOptions.IgnoreCase) && ContainsStrongCheatContext(value));
        }

        private static string GuessProjectRoot(string path)
        {
            try
            {
                string dir = File.Exists(path) ? Path.GetDirectoryName(path) : path;
                if (string.IsNullOrWhiteSpace(dir)) return path ?? "";

                var current = new DirectoryInfo(dir);
                for (int i = 0; i < 7 && current != null; i++, current = current.Parent)
                {
                    if (SafeEnumerateFiles(current.FullName, "*.sln", SearchOption.TopDirectoryOnly).Any() ||
                        SafeEnumerateFiles(current.FullName, "*.vcxproj", SearchOption.TopDirectoryOnly).Any() ||
                        SafeEnumerateFiles(current.FullName, "*.csproj", SearchOption.TopDirectoryOnly).Any()) return current.FullName;
                }

                string knownContainerRoot = NormalizeProjectRootByKnownContainers(dir);
                if (!string.IsNullOrWhiteSpace(knownContainerRoot)) return knownContainerRoot;
                string normalized = NormalizeProjectRootByPathMarkers(dir);
                if (!string.IsNullOrWhiteSpace(normalized)) return normalized;
                if (IsUnsafeBroadProjectRoot(dir)) return "";
                return dir;
            }
            catch { return path ?? ""; }
        }

        private static bool IsMeaningfulSourceProjectGroup(SourceProjectSummary s)
        {
            if (s == null || string.IsNullOrWhiteSpace(s.Root)) return false;
            if (IsUnsafeBroadProjectRoot(s.Root)) return false;
            if (IsCommonDependencyOrGeneratedPath(s.Root) && s.DirectSourceCount == 0 && s.MapperCount == 0 && s.InjectorSpooferTraceCount == 0) return false;
            if (s.DirectSourceCount >= 2) return true;
            if (s.MapperCount > 0 || s.InjectorSpooferTraceCount > 0) return true;
            if (s.GeneratedStructure && s.TotalDetections >= 3 && (s.Tokens.Any(IsStrongDirectCheatFileToken) || s.Labels.Any(l => ScannerHelpers.ContainsInsensitive(l, "cheat")))) return true;
            return false;
        }

        private static string NormalizeProjectRootByKnownContainers(string dir)
        {
            if (string.IsNullOrWhiteSpace(dir)) return "";
            var parts = dir.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries).ToList();
            if (parts.Count == 0) return "";
            for (int i = 0; i < parts.Count; i++)
            {
                if (parts[i].Equals("source", StringComparison.OrdinalIgnoreCase) && i + 2 < parts.Count && parts[i + 1].Equals("repos", StringComparison.OrdinalIgnoreCase))
                    return RebuildPathPrefix(parts, i + 3, dir);
                if ((parts[i].Equals("repos", StringComparison.OrdinalIgnoreCase) || parts[i].Equals("projects", StringComparison.OrdinalIgnoreCase)) && i + 1 < parts.Count)
                    return RebuildPathPrefix(parts, i + 2, dir);
                if ((parts[i].Equals("Desktop", StringComparison.OrdinalIgnoreCase) || parts[i].Equals("Downloads", StringComparison.OrdinalIgnoreCase) || parts[i].Equals("Documents", StringComparison.OrdinalIgnoreCase)) && i + 1 < parts.Count)
                    return RebuildPathPrefix(parts, Math.Min(parts.Count, i + 2), dir);
            }
            return "";
        }

        private static string RebuildPathPrefix(List<string> parts, int count, string originalPath)
        {
            count = Math.Max(1, Math.Min(count, parts.Count));
            string prefix = string.Join(Path.DirectorySeparatorChar.ToString(), parts.Take(count));
            if (originalPath.Length >= 2 && originalPath[1] == ':') return prefix;
            if (originalPath.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\" + prefix;
            if (originalPath.StartsWith(@"\", StringComparison.Ordinal)) return @"\" + prefix;
            return prefix;
        }

        private static bool IsUnsafeBroadProjectRoot(string root)
        {
            string normalized = ScannerHelpers.ToLowerSafe((root ?? "").TrimEnd('\\', '/'));
            if (string.IsNullOrWhiteSpace(normalized)) return true;
            string userProfile = ScannerHelpers.ToLowerSafe(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).TrimEnd('\\', '/'));
            if (!string.IsNullOrWhiteSpace(userProfile) && normalized.Equals(userProfile, StringComparison.OrdinalIgnoreCase)) return true;
            if (normalized.EndsWith(@"\users") || normalized.Equals(@"c:\users", StringComparison.OrdinalIgnoreCase)) return true;
            if (normalized.Equals(@"c:\", StringComparison.OrdinalIgnoreCase) || normalized.Equals("c:", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static bool LooksLikeMeaningfulProjectExecutableUsage(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            string file = ScannerHelpers.ToLowerSafe(ScannerHelpers.GetFileNameOnly(value));
            if (!file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !v.Contains(".exe")) return false;
            if (file.Contains("inject") || file.Contains("mapper") || file.Contains("spoofer") || file.Contains("loader") || file.Contains("cheat") || file.Contains("aimbot") || file.Contains("esp") || file.Contains("radar") || file.Contains("trigger")) return true;
            if (v.Contains(@"\x64\release\") || v.Contains(@"\x64\debug\") || v.Contains(@"\build\release\") || v.Contains(@"\bin\release\")) return ContainsStrongCheatContext(v) && !IsGenericProjectStructureOnlyContext(v);
            return false;
        }

        private static bool IsGenericProjectStructureOnlyContext(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            string[] direct = { "aimbot", "triggerbot", "wallhack", "esp.h", "esp.cpp", "radar.h", "radar.cpp", "rcs.h", "rcs.cpp", "chams", "kdmapper", "extreme injector", "spoofer", "cheat loader", "hwid" };
            return !direct.Any(d => v.Contains(d));
        }

        private static string NormalizeProjectRootByPathMarkers(string dir)
        {
            if (string.IsNullOrWhiteSpace(dir)) return "";
            string[] markers =
            {
                "\\build\\_deps\\", "\\build\\cmakefiles\\", "\\build\\release\\", "\\build\\debug\\", "\\build\\",
                "\\x64\\release\\", "\\x64\\debug\\", "\\x86\\release\\", "\\x86\\debug\\",
                "\\bin\\release\\", "\\bin\\debug\\", "\\obj\\", "\\src\\", "\\source\\"
            };
            string lower = ScannerHelpers.ToLowerSafe(dir);
            foreach (string marker in markers)
            {
                int index = lower.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (index > 0)
                {
                    return dir.Substring(0, index);
                }
            }
            return "";
        }

        private static List<CheatingTimelineEvent> BuildCheatingTimeline(List<FileNameMatch> fileMatches, List<BrowserHistoryMatch> browserMatches, List<BrowserDownloadMatch> browserDownloads, List<ExecutionArtifact> executionArtifacts, List<RuntimeArtifact> runtimeArtifacts, List<SourceProjectSummary> sourceProjects)
        {
            var events = new List<CheatingTimelineEvent>();
            foreach (var e in executionArtifacts.Take(200)) events.Add(new CheatingTimelineEvent { When = e.When, EventType = "Launch trace", Source = e.Source, Summary = e.Label, Evidence = e.Path + " " + e.Details, TimeType = "Windows launch trace time", Severity = e.Severity, Confidence = e.Confidence });
            foreach (var d in browserDownloads.Take(200))
            {
                string evidence = string.IsNullOrWhiteSpace(d.Url) ? d.Snippet : d.Url;
                if (!IsLowContextBrowserTimelineNoise(d.Label, evidence, d.Severity, d.Confidence))
                    events.Add(new CheatingTimelineEvent { When = d.When, EventType = "Browser evidence", Source = d.Browser + " " + d.Profile, Summary = d.Label, Evidence = evidence, TimeType = d.TimeType, Severity = d.Severity, Confidence = d.Confidence });
            }
            foreach (var f in fileMatches.Where(f => !string.IsNullOrWhiteSpace(f.LastWriteTime)).Take(200)) events.Add(new CheatingTimelineEvent { When = f.LastWriteTime, EventType = "File/folder detection", Source = "File system", Summary = f.Label, Evidence = f.Path, TimeType = "File last changed", Severity = f.Severity, Confidence = f.Confidence });
            foreach (var b in browserMatches.Take(100))
            {
                string evidence = b.Snippet;
                if (!IsLowContextBrowserTimelineNoise(b.Label, evidence, b.Severity, b.Confidence))
                    events.Add(new CheatingTimelineEvent { When = string.IsNullOrWhiteSpace(b.When) ? ScannerHelpers.FileTimeString(b.HistoryPath) : b.When, EventType = "Browser keyword lead", Source = b.Browser + " " + b.Profile, Summary = b.Label, Evidence = evidence, TimeType = string.IsNullOrWhiteSpace(b.TimeType) ? "Browser history file time" : b.TimeType, Severity = b.Severity, Confidence = b.Confidence });
            }
            foreach (var p in sourceProjects.Take(50)) events.Add(new CheatingTimelineEvent { When = LatestSampleTime(p.Samples), EventType = "Source/build group", Source = "File system grouping", Summary = p.Determination, Evidence = p.Root, TimeType = "Newest project file time", Severity = p.MaxSeverity, Confidence = p.MaxConfidence });
            events = MergeDuplicateBrowserTimelineEvents(events);
            events.Sort((a, b) => string.Compare(b.When, a.When, StringComparison.OrdinalIgnoreCase));
            return events.Take(500).ToList();
        }


        private static bool IsLowContextBrowserTimelineNoise(string label, string evidence, Severity severity, int confidence)
        {
            if (severity > Severity.Low || confidence > 50) return false;

            string combined = ScannerHelpers.ToLowerSafe((label ?? "") + " " + (evidence ?? ""));
            if (string.IsNullOrWhiteSpace(combined)) return true;

            if (ContainsAnyInsensitive(combined, "unknowncheats", "cosmocheats", "aimbot", "triggerbot", "wallhack", "spinbot", "ragebot", "kdmapper", "dll injector", "extreme injector", "hwid spoofer", "vanguard bypass", "eac bypass", "battleye bypass", "faceit bypass", "vac", "cs2 esp", "cs2 cheat", "counter-strike 2 hacks", "game hacking and cheats")) return false;

            if (ContainsAnyInsensitive(combined, "chatgpt.com", "docs.github.com", "runelite.net", "account.jagex.com", "youtube.com", "youtu.be", "music", "official video", "forgot password", "github pages", "melonloader", "deepseek.com")) return true;

            return combined.Contains("context-needed");
        }

        private static List<CheatingTimelineEvent> MergeDuplicateBrowserTimelineEvents(List<CheatingTimelineEvent> events)
        {
            var output = new List<CheatingTimelineEvent>();
            var browserGroups = events.Where(IsBrowserTimelineEvent).GroupBy(e => e.Source + "|" + e.When + "|" + BrowserTimelineEvidenceKey(e.Evidence), StringComparer.OrdinalIgnoreCase);
            output.AddRange(events.Where(e => !IsBrowserTimelineEvent(e)));
            foreach (var group in browserGroups)
            {
                var items = group.ToList();
                var best = items.OrderByDescending(e => e.Severity).ThenByDescending(e => e.Confidence).First();
                best.EventType = "Browser evidence";
                best.Summary = CombineTimelineReasons(items.Select(e => e.Summary));
                best.TimeType = CombineTimelineValues(items.Select(e => e.TimeType));
                best.Severity = items.Max(e => e.Severity);
                best.Confidence = items.Max(e => e.Confidence);
                output.Add(best);
            }
            return output;
        }

        private static bool IsBrowserTimelineEvent(CheatingTimelineEvent item)
        {
            return item != null && item.EventType.StartsWith("Browser", StringComparison.OrdinalIgnoreCase);
        }

        private static string BrowserTimelineEvidenceKey(string evidence)
        {
            string value = evidence ?? "";
            int index = value.IndexOf(" | ", StringComparison.Ordinal);
            if (index > 0) value = value.Substring(0, index);
            return ScannerHelpers.ToLowerSafe(value.Trim());
        }

        private static string CombineTimelineReasons(IEnumerable<string> values)
        {
            var reasons = (values ?? Enumerable.Empty<string>()).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToList();
            if (reasons.Count == 0) return "Browser evidence";
            if (reasons.Count == 1) return reasons[0];
            return "Multiple browser signals: " + string.Join("; ", reasons);
        }

        private static string CombineTimelineValues(IEnumerable<string> values)
        {
            return string.Join("; ", (values ?? Enumerable.Empty<string>()).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Take(4));
        }

        private static string LatestSampleTime(IEnumerable<string> paths)
        {
            string latest = "";
            foreach (string path in paths ?? Enumerable.Empty<string>())
            {
                string t = ScannerHelpers.EntryLastWriteTimeString(path);
                if (!string.IsNullOrWhiteSpace(t) && string.Compare(t, latest, StringComparison.OrdinalIgnoreCase) > 0) latest = t;
            }
            return latest;
        }

        private static string BuildSummaryText(ScanReport report, List<HardwareRecord> hardwareRecords, List<DeviceConnectionRecord> deviceRecords, List<DmaDeviceRecord> dmaDeviceRecords, List<FileNameMatch> fileMatches, List<BrowserHistoryMatch> browserMatches, List<BrowserHistorySource> browserHistorySources, List<ExecutionArtifact> executionArtifacts, List<BrowserDownloadMatch> browserDownloadMatches, List<RuntimeArtifact> runtimeArtifacts, List<SourceProjectSummary> sourceProjects, List<CheatingTimelineEvent> cheatingTimeline, string outputDirectory, string htmlPath, string jsonPath, string redactedHtmlPath, string redactedJsonPath, string redactedManifestPath, ReportIntegrityContext integrity)
        {
            ScoreAssessment assessment = ReportWriter.CalculateScoreAssessment(report);
            VerdictAssessment verdict = ReportWriter.BuildVerdict(report, assessment, fileMatches, browserMatches, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects);
            int downloadPaths = browserDownloadMatches.Count(d => !string.IsNullOrWhiteSpace(d.LocalPath));
            var sb = new StringBuilder();
            sb.AppendLine("GamerIntegrity scan result");
            sb.AppendLine("Generated: " + ScannerHelpers.CurrentLocalDisplayTimestamp());
            sb.AppendLine("Report ID: " + integrity.ReportId);
            sb.AppendLine("Scanner version: " + integrity.ScannerVersion);
            sb.AppendLine("Scan start: " + integrity.ScanStartTime);
            sb.AppendLine("Scan end: " + integrity.ScanEndTime);
            sb.AppendLine("Result: " + verdict.Label);
            sb.AppendLine("Result basis: " + verdict.Basis);
            sb.AppendLine("Overall concern: " + assessment.ConcernLevel);
            sb.AppendLine("Signal strength: " + assessment.NormalizedScore + "/100");
            sb.AppendLine("Scan confidence: " + assessment.ReportConfidence + "%");
            sb.AppendLine("Raw signal points: " + report.RawScore);
            sb.AppendLine("Detected flags: " + report.Findings.Count + " total | Cheat-critical: " + ReportWriter.CountCheatCriticalFindings(report.Findings) + " | Critical severity: " + report.Findings.Count(f => f.Severity == Severity.Critical) + " | High severity: " + report.Findings.Count(f => f.Severity == Severity.High) + " | Medium severity: " + report.Findings.Count(f => f.Severity == Severity.Medium));
            sb.AppendLine("Scan limitations / failed reads: " + report.Limitations.Count);
            sb.AppendLine("Hardware records: " + hardwareRecords.Count);
            sb.AppendLine("External USB devices: " + deviceRecords.Count);
            sb.AppendLine("DMA / PCIe review records: " + dmaDeviceRecords.Count + " (present: " + dmaDeviceRecords.Count(d => d.CurrentlyPresent) + ", priority review: " + dmaDeviceRecords.Count(d => d.Severity >= Severity.Medium) + ")");
            sb.AppendLine("File/folder name hits: " + fileMatches.Count);
            sb.AppendLine("Detected browser profiles: " + browserHistorySources.Count);
            sb.AppendLine("Browser/domain keyword hits: " + browserMatches.Count);
            sb.AppendLine("Browser source/download hits: " + browserDownloadMatches.Count + " (download/local-path: " + downloadPaths + ", source/history: " + (browserDownloadMatches.Count - downloadPaths) + ")");
            sb.AppendLine("Launch traces: " + executionArtifacts.Count);
            sb.AppendLine("Running/startup traces: " + runtimeArtifacts.Count);
            sb.AppendLine("Cheat project groups: " + sourceProjects.Count);
            sb.AppendLine("Timeline events: " + cheatingTimeline.Count);
            sb.AppendLine("Installed program/tool hits: " + (report.Findings.Any(f => f.Category == "Installed Programs" && f.Score > 0) ? "yes" : "no"));
            sb.AppendLine("Files: not written during scan. Use Export Redacted or Export Non-Redacted after results load to create files.");
            return sb.ToString();
        }

        internal static FileNameRule AdjustRuleForEvidenceContext(FileNameRule rule, string evidenceValue, string evidenceKind)
        {
            if (rule == null) return null;

            string value = ScannerHelpers.ToLowerSafe(evidenceValue);
            string token = ScannerHelpers.ToLowerSafe(rule.Token);
            string label = NormalizeDetectionLabel(rule.Label);
            bool isBrowser = evidenceKind == "BrowserHistory" || evidenceKind == "BrowserSource" || evidenceKind == "BrowserDownloadLocal" || evidenceKind == "BrowserDownloadRecord";
            bool isUsageTrace = evidenceKind == "ExecutionPrefetch" || evidenceKind == "ExecutionAmCache" || evidenceKind == "RuntimeProcess" || evidenceKind == "RuntimeService" || evidenceKind == "StartupRegistry" || evidenceKind == "ScheduledTask" || evidenceKind.StartsWith("Usage", StringComparison.OrdinalIgnoreCase);
            bool isLocalDownload = evidenceKind == "BrowserDownloadLocal";
            bool isBrowserDownloadRecord = evidenceKind == "BrowserDownloadRecord";
            bool hasStrongContext = ContainsStrongCheatContext(value);
            bool broad = IsBroadWeakToken(token) || IsBroadRuleLabel(rule.Label);
            bool contextOnlyHistory = IsContextOnlyHistoryEvidenceKind(evidenceKind);
            bool genericProjectToken = IsGenericProjectStructureToken(token);

            if (IsKnownBenignContextMatch(value, token, evidenceKind, hasStrongContext, broad)) return null;
            if (isBrowserDownloadRecord) hasStrongContext = true;

            if (isUsageTrace && genericProjectToken && !IsStrongUsageToken(token))
            {
                if (!LooksLikeMeaningfulProjectExecutableUsage(value)) return null;
            }

            if (evidenceKind == "FileName" && genericProjectToken)
            {
                if (IsCommonDependencyOrGeneratedPath(value)) return null;
                if (!hasStrongContext) return null;
            }

            Severity severity = rule.Severity;
            int confidence = rule.Confidence;
            int score = rule.Score;

            if (broad)
            {
                label = token == "" ? "Context-needed keyword hit" : (IsVeryBroadWeakToken(token) ? "Context-needed keyword hit" : "Weak keyword hit");
                confidence = Math.Min(confidence, hasStrongContext ? 56 : 44);
                score = Math.Min(score, hasStrongContext ? 8 : 3);
                severity = Severity.Low;
            }

            if (evidenceKind == "FileName" && genericProjectToken)
            {
                label = "Supporting project-structure context";
                confidence = Math.Min(confidence, 52);
                score = Math.Min(score, 5);
                severity = Severity.Low;
            }

            if (contextOnlyHistory)
            {
                confidence = Math.Min(confidence, IsStrongUsageToken(token) || hasStrongContext ? 72 : 50);
                score = Math.Min(score, IsStrongUsageToken(token) || hasStrongContext ? 16 : 5);
                if (severity > Severity.Medium) severity = Severity.Medium;
            }

            if (IsContextSensitiveSingleWord(token) && !hasStrongContext)
            {
                confidence = Math.Min(confidence, 50);
                score = Math.Min(score, 6);
                severity = Severity.Low;
                label = "Context-needed keyword hit";
            }

            if (isBrowser && !hasStrongContext && IsShortOrRiskyToken(token))
            {
                confidence = Math.Min(confidence, 44);
                score = Math.Min(score, 4);
                severity = Severity.Low;
                label = "Context-needed keyword hit";
            }

            if (isUsageTrace)
            {
                if (genericProjectToken && !IsStrongUsageToken(token))
                {
                    label = "Project executable activity context";
                    confidence = Math.Min(confidence, contextOnlyHistory ? 55 : 64);
                    score = Math.Min(score, contextOnlyHistory ? 6 : 10);
                    if (severity > Severity.Medium) severity = Severity.Medium;
                }
                else if (IsStrongUsageToken(token) || hasStrongContext)
                {
                    confidence = Math.Min(96, confidence + 8);
                    int boost = evidenceKind == "ExecutionPrefetch" ? 18 : (contextOnlyHistory ? 0 : (evidenceKind.StartsWith("Usage", StringComparison.OrdinalIgnoreCase) ? 8 : 12));
                    score = Math.Min(contextOnlyHistory ? 18 : 90, score + boost);
                    if (!contextOnlyHistory && severity < Severity.High && IsStrongUsageToken(token)) severity = Severity.High;
                    if (contextOnlyHistory)
                    {
                        if (severity > Severity.Medium) severity = Severity.Medium;
                        confidence = Math.Min(confidence, 72);
                    }
                    label = NormalizeUsageLabel(label, token, evidenceKind);
                }
                else if (broad)
                {
                    confidence = Math.Min(confidence, 48);
                    score = Math.Min(score, 4);
                    severity = Severity.Low;
                }
            }

            if (evidenceKind == "FileName" && !genericProjectToken && IsHighTrustUserEvidencePath(value) && hasStrongContext)
            {
                confidence = Math.Min(95, confidence + 5);
                score = Math.Min(90, score + 8);
            }

            if (isLocalDownload && hasStrongContext)
            {
                confidence = Math.Min(95, confidence + 5);
                score = Math.Min(85, score + 8);
                if (severity < Severity.Medium) severity = Severity.Medium;
            }

            return new FileNameRule
            {
                Token = rule.Token,
                Category = rule.Category,
                Label = label,
                Severity = severity,
                Confidence = ScannerHelpers.Clamp(confidence, 0, 100),
                Score = Math.Max(0, score)
            };
        }

        private static bool IsContextOnlyHistoryEvidenceKind(string evidenceKind)
        {
            return evidenceKind == "UsageJumpList"
                || evidenceKind == "UsageShellBag"
                || evidenceKind == "UsageRecentDocs"
                || evidenceKind == "UsageMountedDevice"
                || evidenceKind == "UsageDefenderHistory"
                || evidenceKind == "UsageEventLog"
                || evidenceKind == "UsageSrum";
        }

        private static bool IsGenericProjectStructureToken(string token)
        {
            string[] tokens = { "src", "source", "driver", "driver.h", "driver.cpp", "driver.hpp", "loader", "loader.h", "loader.cpp", "loader.hpp", "sdk", "dump", "dumper", "client", "client dll" };
            return tokens.Any(t => string.Equals(t, token, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsCommonDependencyOrGeneratedPath(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            string[] markers =
            {
                "\\_deps\\", "\\cmakefiles\\", "\\json-src\\", "\\json-subbuild\\", "\\json-populate-prefix\\",
                "\\imgui-src\\", "\\imgui-subbuild\\", "\\imgui-populate-prefix\\", "\\tests\\", "\\test\\",
                "\\examples\\", @"\example_", "\\thirdparty\\", "\\third_party\\", "\\benchmarks\\", "\\fuzzer\\",
                "\\external\\", "\\vendor\\", "\\packages\\", "\\node_modules\\"
            };
            return markers.Any(m => v.Contains(m));
        }

        private static bool IsStrongDirectCheatFileToken(string token)
        {
            string[] tokens =
            {
                "aimbot", "aimbot.h", "aimbot.cpp", "triggerbot", "triggerbot.h", "triggerbot.cpp",
                "esp.h", "esp.cpp", "radar.h", "radar.cpp", "rcs.h", "rcs.cpp", "chams.h", "chams.cpp",
                "wallhack", "ragebot", "legitbot", "silent aim", "norecoil", "kdmapper", "driver mapper",
                "manual mapper", "manualmap", "extreme injector", "injector", "hwid spoofer", "spoofer", "trace cleaner"
            };
            return tokens.Any(t => string.Equals(t, token, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsUsefulSrumSnippet(string snippet, string token)
        {
            string value = ScannerHelpers.ToLowerSafe(snippet);
            string t = ScannerHelpers.ToLowerSafe(token);
            bool hasPathOrExe = value.Contains(".exe") || value.Contains("\\users\\") || value.Contains("\\program files\\") || value.Contains("\\device\\harddisk") || value.Contains("c:\\");
            if (!hasPathOrExe) return false;
            if ((IsShortOrRiskyToken(t) || IsVeryBroadWeakToken(t)) && !ContainsStrongCheatContext(value)) return false;
            if (value.Contains("srudb.dat") && !ContainsStrongCheatContext(value)) return false;
            return true;
        }

        private static bool IsKnownBenignContextMatch(string value, string token, string evidenceKind, bool hasStrongContext, bool broad)
        {
            if (string.IsNullOrWhiteSpace(value)) return false;

            if (IsNormalFrameworkOrVendorPath(value, token) && !hasStrongContext) return true;
            if (IsNormalPackagedAppOrSecurityPath(value, token) && !hasStrongContext) return true;

            if ((evidenceKind == "RuntimeService" || evidenceKind == "RuntimeProcess" || evidenceKind == "ScheduledTask") && IsNormalWindowsOrVendorRuntime(value, token) && !hasStrongContext) return true;

            if ((evidenceKind == "FileName" || evidenceKind == "BrowserDownloadLocal") && IsNormalFrameworkBinary(value, token) && !hasStrongContext) return true;

            if (evidenceKind == "Installed")
            {
                if (value.Contains("microsoft .net host fx resolver") || value.Contains("microsoft .net host") || value.Contains("windows desktop runtime")) return true;
                if (IsVeryBroadWeakToken(token) && !hasStrongContext) return true;
            }

            if ((evidenceKind == "BrowserHistory" || evidenceKind == "BrowserSource") && broad && !hasStrongContext) return false;

            return false;
        }

        private static bool IsNormalPackagedAppOrSecurityPath(string value, string token)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            string t = ScannerHelpers.ToLowerSafe(token);
            if (v.Contains(@"\program files\windowsapps\") || v.Contains(@"\program files (x86)\windowsapps\")) return true;
            if (v.Contains("wingetdownloader.exe") || v.Contains("sensesampleuploader.exe")) return true;
            if (v.Contains(@"\windows defender advanced threat protection\") || v.Contains(@"\microsoft\windows defender\")) return true;
            if ((t == "loader exe" || t == "loader" || t == "source" || t == "client" || t == "driver" || t == "trace") && (v.Contains(@"\program files\") || v.Contains(@"\program files (x86)\"))) return true;
            return false;
        }

        private static bool IsNormalFrameworkOrVendorPath(string value, string token)
        {
            if (value.Contains("\\gamerintegrity\\") && (value.Contains("\\bin\\release\\net") || value.Contains("\\bin\\debug\\net"))) return true;
            if (value.Contains("\\program files\\dotnet\\") || value.Contains("\\program files (x86)\\dotnet\\")) return true;
            if (value.Contains("microsoft .net host fx resolver")) return true;
            if (value.Contains("system.runtime.loader.dll")) return true;
            if (value.Contains("system.resources.") && value.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return true;
            if (value.Contains("system.xaml.resources.dll")) return true;
            if (value.Contains("presentationframework.resources.dll") || value.Contains("presentationcore.resources.dll") || value.Contains("presentationui.resources.dll")) return true;
            if (value.Contains("windowsbase.resources.dll") || value.Contains("reachframework.resources.dll")) return true;
            if (value.Contains("uiautomationclient.dll") || value.Contains("uiautomationclient.resources.dll") || value.Contains("uiautomationprovider.resources.dll") || value.Contains("uiautomationtypes.resources.dll")) return true;
            if (value.Contains("system.net.webclient.dll") || value.Contains("system.net.websockets.client.dll")) return true;
            if (value.Contains("system.diagnostics.tracesource.dll") || value.Contains("system.diagnostics.diagnosticsource.dll")) return true;
            if (value.Contains("vulkandriverquery.exe") || value.Contains("vulkandriverquery64.exe")) return true;
            if (value.Contains("gameoverlayui.exe") || value.Contains("gameoverlayui64.exe")) return true;
            if (value.Contains("\\windows\\system32\\driverstore\\") && (IsBroadWeakToken(token) || token == "driver" || token == "kernel" || token == "source")) return true;
            if (value.Contains("\\windows\\system32\\drivers\\") && (IsBroadWeakToken(token) || token == "driver" || token == "kernel" || token == "source")) return true;
            if (value.Contains("\\windows\\system32\\drivers\\wdf01000.sys") || value.Contains("\\windows\\system32\\drivers\\ehstortcgdrv.sys")) return true;
            return false;
        }

        private static bool IsNormalFrameworkBinary(string value, string token)
        {
            string file = ScannerHelpers.ToLowerSafe(ScannerHelpers.GetFileNameOnly(value));
            if (file.Length == 0) return false;
            if (file.StartsWith("system.", StringComparison.OrdinalIgnoreCase) && file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return true;
            if (file.StartsWith("microsoft.", StringComparison.OrdinalIgnoreCase) && file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return true;
            if (file.StartsWith("presentation", StringComparison.OrdinalIgnoreCase) && file.EndsWith(".resources.dll", StringComparison.OrdinalIgnoreCase)) return true;
            if (file.StartsWith("uiautomation", StringComparison.OrdinalIgnoreCase) && file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return true;
            if (file.EndsWith(".resources.dll", StringComparison.OrdinalIgnoreCase) && (token == "source" || token == "client dll" || token == "loader.dll" || token == "sdk")) return true;
            return false;
        }

        private static bool IsNormalWindowsOrVendorRuntime(string value, string token)
        {
            if (value.Contains("hp omen hsa service") || value.Contains("hp network hsa service") || value.Contains("hp diagnostics hsa service") || value.Contains("hp app helper hsa service") || value.Contains("hp system info hsa service")) return true;
            if (value.Contains("\\hpomencustomcapcomp.inf_") || value.Contains("\\hpcustomcapcomp.inf_")) return true;
            if (value.Contains("\\omencap\\omencap.exe") || value.Contains("\\networkcap.exe") || value.Contains("\\apphelpercap.exe") || value.Contains("\\diagscap.exe") || value.Contains("\\sysinfocap.exe")) return true;
            if (value.Contains("kernel mode driver frameworks service") || value.Contains("wdf01000.sys")) return true;
            if (value.Contains("microsoft driver for storage devices") || value.Contains("ehstortcgdrv.sys")) return true;
            if (value.Contains("\\windows\\system32\\driverstore\\") && (IsBroadWeakToken(token) || token == "driver" || token == "kernel" || token == "source")) return true;
            if (value.Contains("\\windows\\system32\\drivers\\") && (IsBroadWeakToken(token) || token == "driver" || token == "kernel" || token == "source")) return true;
            return false;
        }

        private static bool ContainsStrongCheatContext(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            string[] strongTokens =
            {
                "unknowncheats", "elitepvpers", "hackforums", "cheatforums", "only-cheats", "cosmocheats", "kernaim", "disconnectcheats", "lethality", "evicted", "vgc.wtf",
                "aimbot", "triggerbot", "wallhack", "esp", "radar", "chams", "silent aim", "ragebot", "legitbot", "spinbot", "norecoil", "no recoil", "skin changer", "skinchanger",
                "kdmapper", "driver mapper", "manual mapper", "manualmap", "extreme injector", "injector", "spoofer", "hwid", "vanguard bypass", "eac bypass", "battleye bypass",
                "cheat loader", "private loader", "p2c loader", "loader auth", "keyauth loader", "cheat source", "cheat project", "cs2 cheat", "rust cheat", "valorant cheat", "fortnite cheat",
                "cs2ext", "cs2-dumper", "client_dll", "offsets.json", "aimbot.h", "esp.h", "radar.h", "rcs.h", "loader.exe", "mapper.exe", "spoofer.exe"
            };
            foreach (string token in strongTokens)
            {
                if (token.Length <= 3)
                {
                    if (ScannerHelpers.RuleMatchesName(v, token)) return true;
                }
                else if (v.Contains(token)) return true;
            }
            return false;
        }

        private static bool IsHighTrustUserEvidencePath(string value)
        {
            return value.Contains("\\desktop\\") || value.Contains("\\downloads\\") || value.Contains("\\documents\\") || value.Contains("\\source\\") || value.Contains("\\repos\\") || value.Contains("\\projects\\") || value.Contains("\\x64\\release\\") || value.Contains("\\x64\\debug\\") || value.Contains(".sln") || value.Contains(".vcxproj") || value.Contains(".cpp") || value.Contains(".hpp") || value.Contains(".h") || value.Contains(".cs") || value.Contains(".sys") || value.Contains(".exe") || value.Contains(".dll");
        }

        private static bool IsStrongUsageToken(string token)
        {
            string[] tokens = { "kdmapper", "driver mapper", "manual mapper", "manualmap", "extreme injector", "injector", "cheat engine", "cheatengine", "wemod", "hwid spoofer", "spoofer", "trace cleaner", "loader.exe", "cheat loader", "private loader", "aimbot", "triggerbot", "wallhack", "esp", "radar", "silent aim", "vanguard bypass", "eac bypass", "battleye bypass" };
            return tokens.Any(t => string.Equals(t, token, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsShortOrRiskyToken(string token)
        {
            string[] tokens = { "esp", "rcs", "fov", "r0", "r3", "aa", "km", "um", "w2s", "rpm", "wpm", "auth", "panel", "menu", "driver", "source", "client", "private", "external", "internal", "sdk", "dump", "loader", "resolver" };
            return tokens.Any(t => string.Equals(t, token, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsContextSensitiveSingleWord(string token)
        {
            string[] tokens = { "source", "driver", "client", "resolver", "private", "internal", "external", "menu", "panel", "auth", "sdk", "dump", "dumper", "trace", "traces", "loader", "overlay", "kernel", "bypass" };
            return tokens.Any(t => string.Equals(t, token, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsBroadWeakToken(string token)
        {
            string[] tokens = { "cheat", "hack", "hacks", "trainer", "modmenu", "mod-menu", "executor", "exploit", "overlay", "paste", "crack", "offsets", "netvars", "signatures", "patternscan", "sigscan", "w2s", "rpm", "wpm", "r0", "r3", "eac", "battleye", "vanguard", "faceit", "ricochet", "vgk", "vgc", "dse", "patchguard", "unban", "spoof", "serials", "slotted", "external", "internal", "menu", "driver", "sdk", "dump", "dumper", "trace", "traces", "private", "invite", "auth", "panel", "source", "src", "project", "provider", "client dll", "resolver", "loader.dll", "dayzero", "slapp", "antic" };
            return tokens.Any(t => string.Equals(t, token, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsVeryBroadWeakToken(string token)
        {
            string[] tokens = { "external", "internal", "menu", "driver", "sdk", "dump", "dumper", "trace", "traces", "private", "invite", "auth", "panel", "source", "src", "project", "provider", "client dll", "resolver", "loader.dll", "overlay", "dayzero", "slapp", "antic" };
            return tokens.Any(t => string.Equals(t, token, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsBroadRuleLabel(string label)
        {
            string lower = ScannerHelpers.ToLowerSafe(label);
            return lower.Contains("weak keyword") || lower.Contains("context-needed") || lower.Contains("broad single-word") || lower.Contains("very broad") || lower.Contains("possible tool keyword");
        }

        private static string NormalizeDetectionLabel(string label)
        {
            if (string.IsNullOrWhiteSpace(label)) return "Possible cheat-related term";
            string lower = ScannerHelpers.ToLowerSafe(label);
            if (lower.Contains("broad single-word") || lower.Contains("very broad")) return "Context-needed keyword hit";
            if (lower.Contains("single-word")) return "Possible cheat-related term";
            return label.Replace("cheat-adjacent", "context-needed");
        }

        private static string NormalizeUsageLabel(string label, string token, string evidenceKind)
        {
            string lower = ScannerHelpers.ToLowerSafe(label + " " + token);
            string subject = "Tool";
            if (lower.Contains("inject")) subject = "Injector";
            else if (lower.Contains("mapper") || lower.Contains("kdmapper") || lower.Contains("driver mapper")) subject = "Driver mapper";
            else if (lower.Contains("loader")) subject = "Cheat loader";
            else if (lower.Contains("spoofer") || lower.Contains("hwid")) subject = "Spoofer";
            else if (lower.Contains("bypass")) subject = "Anti-cheat bypass";
            else if (lower.Contains("aimbot") || lower.Contains("triggerbot") || lower.Contains("esp") || lower.Contains("radar")) subject = "Cheat feature";

            switch (evidenceKind)
            {
                case "ExecutionPrefetch": return subject + " launch trace";
                case "ExecutionAmCache": return subject + " application-history trace";
                case "RuntimeProcess": return subject + " running process";
                case "RuntimeService": return subject + " service/driver entry";
                case "StartupRegistry": return subject + " startup registry entry";
                case "ScheduledTask": return subject + " scheduled-task entry";
                case "UsageUserAssist": return subject + " Explorer launch history";
                case "UsageBamDam": return subject + " recent app activity";
                case "UsageJumpList": return subject + " recent item trace";
                case "UsageShellBag": return subject + " folder history trace";
                case "UsageRunMru": return subject + " Run box history trace";
                case "UsageRecentDocs": return subject + " recent file/dialog history";
                case "UsageMountedDevice": return subject + " mounted-device history";
                case "UsageDefenderHistory": return subject + " Defender history trace";
                case "UsageEventLog": return subject + " event-log trace";
                case "UsageSrum": return subject + " SRUM app-activity trace";
                default: return subject + " usage trace";
            }
        }

        internal static FileNameRule BestRuleMatch(string value, List<FileNameRule> rules)
        {
            if (string.IsNullOrWhiteSpace(value) || rules == null || rules.Count == 0) return null;

            string normalizedValue = ScannerHelpers.NormalizeNameForMatch(value);
            string paddedNormalizedValue = " " + normalizedValue + " ";
            string lowerValue = ScannerHelpers.ToLowerSafe(value);
            string compactValue = null;

            FileNameRule best = null;
            foreach (var rule in rules)
            {
                if (rule == null || string.IsNullOrWhiteSpace(rule.Token)) continue;

                string normalizedToken = ScannerHelpers.NormalizeNameForMatch(rule.Token);
                if (normalizedToken.Length == 0) continue;

                bool matched = paddedNormalizedValue.Contains(" " + normalizedToken + " ");

                if (!matched)
                {
                    string lowerToken = ScannerHelpers.ToLowerSafe(rule.Token);
                    matched = lowerToken.Length >= 6 && lowerValue.Contains(lowerToken);

                    if (!matched)
                    {
                        if (compactValue == null) compactValue = CompactAlphaNumeric(lowerValue);
                        string compactToken = CompactAlphaNumeric(lowerToken);
                        matched = compactToken.Length >= 8 && compactValue.Contains(compactToken);
                    }
                }

                if (!matched) continue;

                if (best == null || rule.Score > best.Score ||
                    (rule.Score == best.Score && rule.Confidence > best.Confidence) ||
                    (rule.Score == best.Score && rule.Confidence == best.Confidence && rule.Severity > best.Severity))
                {
                    best = rule;
                }
            }

            return best;
        }

        private static string CompactAlphaNumeric(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            var sb = new StringBuilder(value.Length);
            foreach (char ch in value)
            {
                if (char.IsLetterOrDigit(ch)) sb.Append(char.ToLowerInvariant(ch));
            }
            return sb.ToString();
        }

        private static IEnumerable<string> SafeEnumerateFiles(string dir, string pattern, SearchOption option, ScanReport report = null, string scope = "")
        {
            if (string.IsNullOrWhiteSpace(dir)) yield break;

            var pending = new Stack<string>();
            pending.Push(dir);
            string safePattern = string.IsNullOrWhiteSpace(pattern) ? "*" : pattern;

            while (pending.Count > 0)
            {
                string current = pending.Pop();

                string[] files = Array.Empty<string>();
                try { files = Directory.GetFiles(current, safePattern); } catch (Exception ex) { AddEnumerationLimitation(report, scope, current, "Files could not be listed: " + ex.Message); }
                foreach (string file in files) yield return file;

                if (option != SearchOption.AllDirectories) continue;

                string[] dirs = Array.Empty<string>();
                try { dirs = Directory.GetDirectories(current); } catch (Exception ex) { AddEnumerationLimitation(report, scope, current, "Folders could not be listed: " + ex.Message); }
                foreach (string child in dirs)
                {
                    if (!IsReparsePoint(child)) pending.Push(child);
                }
            }
        }

        private static IEnumerable<string> SafeEnumerateDirectories(string dir, ScanReport report = null, string scope = "")
        {
            if (string.IsNullOrWhiteSpace(dir)) yield break;

            string[] dirs = Array.Empty<string>();
            try { dirs = Directory.GetDirectories(dir); } catch (Exception ex) { AddEnumerationLimitation(report, scope, dir, "Folders could not be listed: " + ex.Message); }
            foreach (string child in dirs)
            {
                if (!IsReparsePoint(child)) yield return child;
            }
        }

        private static void AddEnumerationLimitation(ScanReport report, string scope, string path, string message)
        {
            if (report == null) return;
            if (report.Limitations.Count(l => string.Equals(l.Source, "File system", StringComparison.OrdinalIgnoreCase)) >= 80) return;
            report.AddLimitation("File system", string.IsNullOrWhiteSpace(scope) ? "Enumeration" : scope, path, ScannerHelpers.CollapseWhitespaceForDisplay(message), Severity.Low);
        }

        private static bool IsReparsePoint(string path)
        {
            try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
            catch { return true; }
        }

        private static string ReadBinaryAsText(string path, int maxBytes)
        {
            if (string.IsNullOrWhiteSpace(path) || maxBytes <= 0) return "";

            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    int remaining = (int)Math.Min(Math.Min(fs.Length, maxBytes), int.MaxValue);
                    if (remaining <= 0) return "";

                    var ascii = new StringBuilder(remaining);
                    byte[] buffer = new byte[Math.Min(64 * 1024, remaining)];

                    while (remaining > 0)
                    {
                        int wanted = Math.Min(buffer.Length, remaining);
                        int read = fs.Read(buffer, 0, wanted);
                        if (read <= 0) break;

                        for (int i = 0; i < read; i++)
                        {
                            byte b = buffer[i];
                            ascii.Append(b >= 32 && b <= 126 ? (char)b : ' ');
                        }

                        remaining -= read;
                    }

                    return ascii.ToString();
                }
            }
            catch { return ""; }
        }

        private static string Snippet(string data, int pos, int tokenLength)
        {
            int start = Math.Max(0, pos - 140);
            int end = Math.Min(data.Length, pos + Math.Max(tokenLength, 1) + 180);
            return data.Substring(start, end - start);
        }

    }
}
