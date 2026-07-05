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
        private const int MaxFileNameMatches = 3000;
        private const int MaxScannedFileSystemEntries = 250000;
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
                Notify(progress, 3, "Getting the scan ready...");
                CollectRuntimePrivilegeInfo(report);

                Notify(progress, 10, "Reading Windows version and compatibility details...");
                CollectOsCompatibilityInfo(report);
                Notify(progress, 14, "Windows compatibility details captured.");

                Notify(progress, 22, "Measuring network and display inventory...");
                CollectNetworkAndDisplayInfo(report);
                Notify(progress, 26, "Network and display inventory captured.");

                Notify(progress, 34, "Reading Windows Security Center antivirus state...");
                CollectAntivirusInfo(report);
                Notify(progress, 38, "Windows Security Center antivirus state captured.");

                Notify(progress, 46, "Reading Secure Boot, TPM, VBS/HVCI, BCD, and driver-blocklist state...");
                CollectBootSecurityInfo(report);
                Notify(progress, 50, "Boot security settings captured.");

                Notify(progress, 54, "Checking installed programs for cheat, trainer, decompiler, debugger, and process-inspection tools...");
                installedProgramMatches = ScanInstalledProgramIndicators(report);
                Notify(progress, 58, "Installed program check complete: " + installedProgramMatches.Count + " flagged tool/program detection(s).");

                Notify(progress, 60, "Checking AmCache and Prefetch for cheat/tool execution traces...");
                executionArtifacts = ScanAmCacheAndPrefetchEvidence(report);
                Notify(progress, 62, "Execution evidence check complete: " + executionArtifacts.Count + " AmCache/Prefetch trace(s).");

                Notify(progress, 64, "Checking running processes, services, driver entries, scheduled tasks, and startup entries...");
                runtimeArtifacts = ScanRuntimeStartupServiceEvidence(report);
                Notify(progress, 66, "Runtime/startup check complete: " + runtimeArtifacts.Count + " active or persistent artifact(s).");

                Notify(progress, 68, "Enumerating driver services, signatures, hashes, and services...");
                drivers = CollectDriverInfo(report);
                Notify(progress, 72, "Driver/service inventory complete: " + drivers.Count + " driver service(s) inspected.");

                Notify(progress, 76, "Collecting board, BIOS, disk, and network-adapter identity records...");
                CollectHardwareIdentityInfo(report, hardwareRecords);
                Notify(progress, 80, "Hardware identity collection complete: " + hardwareRecords.Count + " record(s) captured.");

                Notify(progress, 84, "Reading retained USB and USB-storage connection history...");
                CollectExternalDeviceInfo(report, deviceRecords);
                Notify(progress, 86, "USB history collection complete: " + deviceRecords.Count + " device record(s) captured.");

                Notify(progress, 88, "Detecting browser profiles and scanning local history keyword hits...");
                browserMatches = ScanBrowserHistoryKeywords(report, browserHistorySources);
                Notify(progress, 90, "Browser/domain keyword scan complete: " + browserMatches.Count + " keyword detection(s) across " + browserHistorySources.Count + " detected profile(s).");

                Notify(progress, 91, "Checking browser source/download records and local path traces...");
                browserDownloadMatches = ScanBrowserDownloadEvidence(report, browserHistorySources);
                Notify(progress, 92, "Browser source/download evidence check complete: " + browserDownloadMatches.Count + " record(s).");

                if (options.IncludeFileNameScan)
                {
                    Notify(progress, 93, "Scanning common user and developer folders for cheat/source/build file names...");
                    fileMatches = ScanScopedFileNames(report);
                    Notify(progress, 95, "File/folder name scan complete: " + fileMatches.Count + " match(es).");
                }

                Notify(progress, 96, "Grouping source/build detections and building evidence timeline...");
                sourceProjects = AnalyzeSourceProjects(report, fileMatches, executionArtifacts, runtimeArtifacts);
                cheatingTimeline = BuildCheatingTimeline(fileMatches, browserMatches, browserDownloadMatches, executionArtifacts, runtimeArtifacts, sourceProjects);

                integrity.ScanEndTime = ScannerHelpers.CurrentLocalTimestamp();

                string htmlPath = Path.Combine(outputDirectory, "GamerIntegrity_Report.html");
                string jsonPath = Path.Combine(outputDirectory, "GamerIntegrity_Report.json");
                string redactedHtmlPath = Path.Combine(outputDirectory, "GamerIntegrity_Report_Redacted.html");
                string redactedJsonPath = Path.Combine(outputDirectory, "GamerIntegrity_Report_Redacted.json");
                integrity.ManifestPath = Path.Combine(outputDirectory, "GamerIntegrity_Report_Integrity.json");
                string redactedManifestPath = Path.Combine(outputDirectory, "GamerIntegrity_Report_Redacted_Integrity.json");

                Notify(progress, 98, "Preparing in-app scan results...");
                string jsonContent = ReportWriter.BuildJsonReport(report, drivers, hardwareRecords, deviceRecords, installedProgramMatches, fileMatches,
                    browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects,
                    cheatingTimeline, integrity, false);
                string htmlContent = ReportWriter.BuildHtmlReport(report, drivers, hardwareRecords, deviceRecords, installedProgramMatches, fileMatches,
                    browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects,
                    cheatingTimeline, integrity, false);
                string redactedJsonContent = ReportWriter.BuildJsonReport(report, drivers, hardwareRecords, deviceRecords, installedProgramMatches, fileMatches,
                    browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects,
                    cheatingTimeline, integrity, true);
                string redactedHtmlContent = ReportWriter.BuildHtmlReport(report, drivers, hardwareRecords, deviceRecords, installedProgramMatches, fileMatches,
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
                    Notify(progress, 99, "Exporting selected scan files...");
                    bool wroteJson = ReportWriter.WriteJsonReport(report, drivers, hardwareRecords, deviceRecords, installedProgramMatches, fileMatches,
                        browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects,
                        cheatingTimeline, integrity, jsonPath, false);
                    bool wroteHtml = ReportWriter.WriteHtmlReport(report, drivers, hardwareRecords, deviceRecords, installedProgramMatches, fileMatches,
                        browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects,
                        cheatingTimeline, integrity, htmlPath, false);
                    bool wroteRedactedJson = ReportWriter.WriteJsonReport(report, drivers, hardwareRecords, deviceRecords, installedProgramMatches, fileMatches,
                        browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects,
                        cheatingTimeline, integrity, redactedJsonPath, true);
                    bool wroteRedactedHtml = ReportWriter.WriteHtmlReport(report, drivers, hardwareRecords, deviceRecords, installedProgramMatches, fileMatches,
                        browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects,
                        cheatingTimeline, integrity, redactedHtmlPath, true);
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
                result.SummaryText = BuildSummaryText(report, hardwareRecords, deviceRecords, fileMatches, browserMatches, browserHistorySources,
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
            DeduplicateRuntimeArtifacts(artifacts);
            ScannerHelpers.SortEvidence(artifacts, a => a.Score, a => a.Confidence, a => a.Severity);
            if (artifacts.Count > 0)
            {
                var sample = string.Join("\n", artifacts.Take(12).Select(a => "- " + a.SourceType + ": " + a.Name + " [" + a.Label + "] " + a.Path));
                report.AddFinding("Runtime/Startup", "Runtime/startup indicators found", sample, artifacts.Max(a => a.Severity), Math.Min(95, artifacts.Max(a => a.Confidence)), Math.Min(120, artifacts.Sum(a => a.Score)));
            }
            else report.AddFinding("Runtime/Startup", "No runtime/startup indicators found", "Running processes, services, common startup keys, and scheduled task XML files were checked against local indicators.", Severity.Info, 65, 0);
            return artifacts;
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
                drivers.Add(info);
            }

            var suspicious = drivers.Where(d => d.SuspiciousNamePattern).Take(20).ToList();
            if (suspicious.Count > 0)
            {
                var sample = string.Join("\n", suspicious.Select(d => "- " + d.Name + " | " + d.Path));
                report.AddFinding("Drivers", "Suspicious driver/service name patterns", sample, Severity.Medium, 70, Math.Min(80, suspicious.Count * 15));
            }
            report.AddFinding("Drivers", "Driver service inventory captured", "Driver service entries inspected: " + drivers.Count + "; live device services observed: " + liveDeviceServices.Count + "; signed/trusted binaries: " + drivers.Count(d => d.SignedTrusted) + "; missing binaries: " + drivers.Count(d => !d.FileExists) + ".", Severity.Info, 75, 0);
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

        private static List<BrowserHistoryMatch> ScanBrowserHistoryKeywords(ScanReport report, List<BrowserHistorySource> outSources)
        {
            var sources = DiscoverBrowserHistorySources();
            outSources.AddRange(sources);
            var matches = new List<BrowserHistoryMatch>();
            var rules = Rules.BrowserHistoryRules();

            foreach (var source in sources)
            {
                string data = ReadBinaryAsText(source.HistoryPath, MaxHistoryBytes);
                if (data.Length == 0) continue;
                string lower = data.ToLowerInvariant();
                foreach (var rule in rules)
                {
                    foreach (string variant in BrowserSearchVariants(rule.Token))
                    {
                        int pos = lower.IndexOf(variant.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase);
                        if (pos < 0) continue;
                        string snippet = ScannerHelpers.CollapseWhitespaceForDisplay(Snippet(data, pos, variant.Length));
                        FileNameRule adjustedRule = AdjustRuleForEvidenceContext(rule, snippet, "BrowserHistory");
                        if (adjustedRule == null) continue;
                        matches.Add(new BrowserHistoryMatch
                        {
                            Browser = source.Browser,
                            Profile = source.Profile,
                            HistoryPath = source.HistoryPath,
                            Token = adjustedRule.Token,
                            Label = adjustedRule.Label,
                            Snippet = snippet,
                            Severity = adjustedRule.Severity,
                            Confidence = adjustedRule.Confidence,
                            Score = adjustedRule.Score
                        });
                        break;
                    }
                }
            }
            DeduplicateBrowserMatches(matches);
            ScannerHelpers.SortEvidence(matches, m => m.Score, m => m.Confidence, m => m.Severity);
            if (matches.Count > 0)
            {
                var sample = string.Join("\n", matches.Take(12).Select(m => "- " + m.Browser + " " + m.Profile + ": " + m.Token + " [" + m.Label + "]"));
                report.AddFinding("Browser History", "Browser/domain keyword detections found", sample, matches.Max(m => m.Severity), Math.Min(95, matches.Max(m => m.Confidence)), Math.Min(160, matches.Sum(m => m.Score)));
            }
            else report.AddFinding("Browser History", "No browser/domain keyword detections found", "Detected browser profiles were scanned for local keyword/domain indicators. Profiles found: " + sources.Count + ".", Severity.Info, 60, 0);
            return matches;
        }

        private static List<BrowserDownloadMatch> ScanBrowserDownloadEvidence(ScanReport report, List<BrowserHistorySource> sources)
        {
            var matches = new List<BrowserDownloadMatch>();
            var rules = Rules.BrowserDownloadRules();
            if (sources.Count == 0) sources = DiscoverBrowserHistorySources();
            foreach (var source in sources)
            {
                string data = ReadBinaryAsText(source.HistoryPath, MaxHistoryBytes);
                if (data.Length == 0) continue;
                string lower = data.ToLowerInvariant();
                foreach (var rule in rules)
                {
                    int pos = lower.IndexOf(rule.Token.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase);
                    if (pos < 0) continue;
                    string snippet = ScannerHelpers.CollapseWhitespaceForDisplay(Snippet(data, pos, rule.Token.Length));
                    string url = ExtractBestUrl(snippet, rule.Token);
                    string local = ExtractFirstWindowsPath(snippet);
                    string evidenceKind = string.IsNullOrWhiteSpace(local) ? "BrowserSource" : "BrowserDownloadLocal";
                    FileNameRule adjustedRule = AdjustRuleForEvidenceContext(rule, url + " " + local + " " + snippet, evidenceKind);
                    if (adjustedRule == null) continue;
                    var match = new BrowserDownloadMatch
                    {
                        Browser = source.Browser,
                        Profile = source.Profile,
                        HistoryPath = source.HistoryPath,
                        Token = adjustedRule.Token,
                        Label = adjustedRule.Label,
                        Url = url,
                        Domain = DomainFromUrl(url),
                        LocalPath = local,
                        EvidenceType = string.IsNullOrWhiteSpace(local) ? "source/history snippet" : "download/local path",
                        Snippet = snippet,
                        When = ScannerHelpers.FileTimeString(source.HistoryPath),
                        TimeType = "History DB last modified",
                        Severity = adjustedRule.Severity,
                        Confidence = string.IsNullOrWhiteSpace(local) ? Math.Max(45, adjustedRule.Confidence - 8) : adjustedRule.Confidence,
                        Score = string.IsNullOrWhiteSpace(local) ? Math.Max(5, adjustedRule.Score - 8) : adjustedRule.Score
                    };
                    if (!IsKnownBenignBrowserDownloadMatch(match)) matches.Add(match);
                }
            }
            DeduplicateBrowserDownloads(matches);
            ScannerHelpers.SortEvidence(matches, m => m.Score, m => m.Confidence, m => m.Severity);
            if (matches.Count > 0)
            {
                var sample = string.Join("\n", matches.Take(12).Select(m => "- " + m.Browser + " " + m.Profile + ": " + m.Token + " | " + (string.IsNullOrWhiteSpace(m.Url) ? m.LocalPath : m.Url)));
                report.AddFinding("Browser Source/Download Evidence", "Browser source/download evidence found", sample, matches.Max(m => m.Severity), Math.Min(95, matches.Max(m => m.Confidence)), Math.Min(160, matches.Sum(m => m.Score)));
            }
            else report.AddFinding("Browser Source/Download Evidence", "No browser source/download evidence found", "Browser history databases were checked for source, download, URL, and local-path traces.", Severity.Info, 60, 0);
            return matches;
        }

        private static bool IsKnownBenignBrowserDownloadMatch(BrowserDownloadMatch match)
        {
            string domain = ScannerHelpers.ToLowerSafe(match.Domain);
            string url = ScannerHelpers.ToLowerSafe(match.Url);
            string local = ScannerHelpers.ToLowerSafe(match.LocalPath);
            string file = ScannerHelpers.ToLowerSafe(ScannerHelpers.GetFileNameOnly(match.LocalPath));
            string token = ScannerHelpers.ToLowerSafe(match.Token);
            bool microsoftDomain = domain == "microsoft.com" || domain == "www.microsoft.com" || domain == "download.microsoft.com" || domain == "aka.ms" || domain.EndsWith(".microsoft.com", StringComparison.OrdinalIgnoreCase);
            if (microsoftDomain && (file.Contains("vcredist") || file.Contains("directx") || file.Contains("dxwebsetup") || file.Contains("dotnet"))) return true;
            if ((token == "loader" || token == "cheat.com" || token == "cheats.com") && microsoftDomain && !ContainsAnySuspiciousBrowserToken(url + " " + local)) return true;
            return false;
        }

        private static bool ContainsAnySuspiciousBrowserToken(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            string[] tokens = { "unknowncheats", "elitepvpers", "aimbot", "triggerbot", "wallhack", "ragebot", "silent aim", "esp", "kdmapper", "driver mapper", "injector", "spoofer", "hwid", "bypass", "dma", "dnspy", "ida", "x64dbg", "wemod", "cosmocheats", "kernaim", "disconnectcheats", "lethality", "evicted" };
            return tokens.Any(t => v.Contains(t));
        }

        private static List<BrowserHistorySource> DiscoverBrowserHistorySources()
        {
            var sources = new List<BrowserHistorySource>();
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            AddChromiumHistorySources(sources, "Chrome", Path.Combine(local, @"Google\Chrome\User Data"));
            AddChromiumHistorySources(sources, "Chrome Beta", Path.Combine(local, @"Google\Chrome Beta\User Data"));
            AddChromiumHistorySources(sources, "Chrome Dev", Path.Combine(local, @"Google\Chrome Dev\User Data"));
            AddChromiumHistorySources(sources, "Chrome Canary", Path.Combine(local, @"Google\Chrome SxS\User Data"));
            AddChromiumHistorySources(sources, "Edge", Path.Combine(local, @"Microsoft\Edge\User Data"));
            AddChromiumHistorySources(sources, "Edge Beta", Path.Combine(local, @"Microsoft\Edge Beta\User Data"));
            AddChromiumHistorySources(sources, "Edge Dev", Path.Combine(local, @"Microsoft\Edge Dev\User Data"));
            AddChromiumHistorySources(sources, "Edge Canary", Path.Combine(local, @"Microsoft\Edge SxS\User Data"));
            AddChromiumHistorySources(sources, "Brave", Path.Combine(local, @"BraveSoftware\Brave-Browser\User Data"));
            AddChromiumHistorySources(sources, "Vivaldi", Path.Combine(local, @"Vivaldi\User Data"));
            AddChromiumHistorySources(sources, "Opera", Path.Combine(roaming, @"Opera Software\Opera Stable"));
            AddChromiumHistorySources(sources, "Opera GX", Path.Combine(roaming, @"Opera Software\Opera GX Stable"));
            AddFirefoxHistorySources(sources, Path.Combine(roaming, @"Mozilla\Firefox\Profiles"));
            return sources;
        }

        private static void AddChromiumHistorySources(List<BrowserHistorySource> sources, string browser, string baseDir)
        {
            if (!Directory.Exists(baseDir)) return;
            foreach (string profile in SafeEnumerateDirectories(baseDir).Take(100))
            {
                string name = Path.GetFileName(profile);
                string history = Path.Combine(profile, "History");
                if (!File.Exists(history)) continue;
                if (!name.Equals("Default", StringComparison.OrdinalIgnoreCase) && !name.StartsWith("Profile", StringComparison.OrdinalIgnoreCase) && !name.Equals("Guest Profile", StringComparison.OrdinalIgnoreCase) && !name.Equals("Opera Stable", StringComparison.OrdinalIgnoreCase) && !name.Equals("Opera GX Stable", StringComparison.OrdinalIgnoreCase))
                {
                    // Keep only real profile folders by requiring a Chromium History database in the folder.
                }
                sources.Add(new BrowserHistorySource { Browser = browser, Profile = name, HistoryPath = history });
            }
            string direct = Path.Combine(baseDir, "History");
            if (File.Exists(direct) && !sources.Any(s => s.HistoryPath.Equals(direct, StringComparison.OrdinalIgnoreCase)))
                sources.Add(new BrowserHistorySource { Browser = browser, Profile = Path.GetFileName(baseDir), HistoryPath = direct });
        }

        private static void AddFirefoxHistorySources(List<BrowserHistorySource> sources, string baseDir)
        {
            if (!Directory.Exists(baseDir)) return;
            foreach (string profile in SafeEnumerateDirectories(baseDir).Take(100))
            {
                string history = Path.Combine(profile, "places.sqlite");
                if (File.Exists(history)) sources.Add(new BrowserHistorySource { Browser = "Firefox", Profile = Path.GetFileName(profile), HistoryPath = history });
            }
        }

        private static List<string> BrowserSearchVariants(string token)
        {
            var variants = new List<string> { token };
            if (token.Contains(" "))
            {
                variants.Add(token.Replace(" ", "+"));
                variants.Add(token.Replace(" ", "%20"));
                variants.Add(token.Replace(" ", "-"));
                variants.Add(token.Replace(" ", "_"));
                variants.Add(token.Replace(" ", ""));
            }
            return variants.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static void DeduplicateBrowserMatches(List<BrowserHistoryMatch> matches)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = matches.Count - 1; i >= 0; i--)
            {
                string key = matches[i].Browser + "|" + matches[i].Profile + "|" + matches[i].Token + "|" + matches[i].Snippet;
                if (!seen.Add(key)) matches.RemoveAt(i);
            }
        }

        private static void DeduplicateBrowserDownloads(List<BrowserDownloadMatch> matches)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = matches.Count - 1; i >= 0; i--)
            {
                string key = matches[i].Browser + "|" + matches[i].Profile + "|" + matches[i].Token + "|" + matches[i].Url + "|" + matches[i].LocalPath;
                if (!seen.Add(key)) matches.RemoveAt(i);
            }
        }

        private static List<FileNameMatch> ScanScopedFileNames(ScanReport report)
        {
            var roots = BuildScanRoots();
            var rules = Rules.FileNameRules();
            var matches = new List<FileNameMatch>();
            int seen = 0;
            foreach (string root in roots)
            {
                foreach (string entry in SafeEnumerateFileSystemEntries(root))
                {
                    if (++seen > MaxScannedFileSystemEntries || matches.Count >= MaxFileNameMatches) break;
                    string name = Path.GetFileName(entry);
                    var best = BestRuleMatch(name, rules);
                    best = AdjustRuleForEvidenceContext(best, entry, "FileName");
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
                report.AddFinding("File Name Scan", "File/folder name detections found", sample, matches.Max(m => m.Severity), Math.Min(95, matches.Max(m => m.Confidence)), Math.Min(200, matches.Sum(m => m.Score)));
            }
            else report.AddFinding("File Name Scan", "No scoped file/folder name detections found", "Common user, developer, and download locations were checked against the local indicator list.", Severity.Info, 65, 0);
            return matches;
        }

        private static List<string> BuildScanRoots()
        {
            var roots = new List<string>();
            Action<string> add = p => { if (!string.IsNullOrWhiteSpace(p) && Directory.Exists(p) && !roots.Contains(p, StringComparer.OrdinalIgnoreCase)) roots.Add(p); };
            add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "source"));
            add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "repos"));
            add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Projects"));
            add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
            return roots;
        }

        private static IEnumerable<string> SafeEnumerateFileSystemEntries(string root)
        {
            var pending = new Stack<string>();
            pending.Push(root);
            while (pending.Count > 0)
            {
                string dir = pending.Pop();
                string[] files = new string[0];
                try { files = Directory.GetFiles(dir); } catch { }
                foreach (string f in files) yield return f;
                string[] dirs = new string[0];
                try { dirs = Directory.GetDirectories(dir); } catch { }
                foreach (string d in dirs)
                {
                    yield return d;
                    if (!ShouldSkipDirectory(d)) pending.Push(d);
                }
            }
        }

        private static bool ShouldSkipDirectory(string path)
        {
            string name = ScannerHelpers.ToLowerSafe(Path.GetFileName(path));
            return name == "node_modules" || name == ".git" || name == ".vs" || name == "packages" || name == "obj" || name == "temp" || name == "cache";
        }

        private static bool IsLikelyBenignFileNameMatch(string path, FileNameRule rule)
        {
            string lower = ScannerHelpers.ToLowerSafe(path);
            if (rule.Token.Equals("loader", StringComparison.OrdinalIgnoreCase) && (lower.Contains("bootloader") || lower.Contains("classloader"))) return true;
            if (rule.Token.Equals("cleaner", StringComparison.OrdinalIgnoreCase) && (lower.Contains("disk cleanup") || lower.Contains("ccleaner browser"))) return true;
            return false;
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
            var projects = map.Values.OrderByDescending(s => s.MaxScore).ThenByDescending(s => s.TotalDetections).ToList();
            if (projects.Count > 0)
            {
                var sample = string.Join("\n", projects.Take(8).Select(p => "- " + p.Determination + ": " + p.Root + " (detections: " + p.TotalDetections + ")"));
                report.AddFinding("Source Projects", "Cheat software/source/build evidence grouped", sample, projects.Max(p => p.MaxSeverity), Math.Min(95, projects.Max(p => p.MaxConfidence)), Math.Min(180, projects.Sum(p => p.MaxScore + p.TotalDetections * 4)));
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
            string combined = ScannerHelpers.ToLowerSafe(m.Token + " " + m.Label + " " + m.Path);
            return combined.Contains("cheat") || combined.Contains("aimbot") || combined.Contains("wallhack") || combined.Contains("esp source") || combined.Contains("source") || combined.Contains("kdmapper") || combined.Contains("spoofer");
        }

        private static bool LooksLikeProjectOrBuildArtifact(string path)
        {
            return Regex.IsMatch(path ?? "", "\\.(sln|vcxproj|csproj|h|hpp|cpp|cxx|cs|pdb|lib|dll|sys|exe)$", RegexOptions.IgnoreCase)
                || Regex.IsMatch(path ?? "", @"\\(bin|obj|x64|x86|release|debug|src|source)\\", RegexOptions.IgnoreCase);
        }

        private static string GuessProjectRoot(string path)
        {
            try
            {
                var dir = File.Exists(path) ? Path.GetDirectoryName(path) : path;
                var current = new DirectoryInfo(dir);
                for (int i = 0; i < 5 && current != null; i++, current = current.Parent)
                {
                    if (SafeEnumerateFiles(current.FullName, "*.sln", SearchOption.TopDirectoryOnly).Any() ||
                        SafeEnumerateFiles(current.FullName, "*.vcxproj", SearchOption.TopDirectoryOnly).Any() ||
                        SafeEnumerateFiles(current.FullName, "*.csproj", SearchOption.TopDirectoryOnly).Any()) return current.FullName;
                }
                return dir;
            }
            catch { return path ?? ""; }
        }

        private static List<CheatingTimelineEvent> BuildCheatingTimeline(List<FileNameMatch> fileMatches, List<BrowserHistoryMatch> browserMatches, List<BrowserDownloadMatch> browserDownloads, List<ExecutionArtifact> executionArtifacts, List<RuntimeArtifact> runtimeArtifacts, List<SourceProjectSummary> sourceProjects)
        {
            var events = new List<CheatingTimelineEvent>();
            foreach (var e in executionArtifacts.Take(200)) events.Add(new CheatingTimelineEvent { When = e.When, EventType = "Execution trace", Source = e.Source, Summary = e.Label, Evidence = e.Path + " " + e.Details, TimeType = "Artifact timestamp", Severity = e.Severity, Confidence = e.Confidence });
            foreach (var d in browserDownloads.Take(200)) events.Add(new CheatingTimelineEvent { When = d.When, EventType = "Browser evidence", Source = d.Browser + " " + d.Profile, Summary = d.Label, Evidence = string.IsNullOrWhiteSpace(d.Url) ? d.Snippet : d.Url, TimeType = d.TimeType, Severity = d.Severity, Confidence = d.Confidence });
            foreach (var f in fileMatches.Where(f => !string.IsNullOrWhiteSpace(f.LastWriteTime)).Take(200)) events.Add(new CheatingTimelineEvent { When = f.LastWriteTime, EventType = "File/folder detection", Source = "File system", Summary = f.Label, Evidence = f.Path, TimeType = "Last write time", Severity = f.Severity, Confidence = f.Confidence });
            foreach (var b in browserMatches.Take(100)) events.Add(new CheatingTimelineEvent { When = ScannerHelpers.FileTimeString(b.HistoryPath), EventType = "Browser keyword lead", Source = b.Browser + " " + b.Profile, Summary = b.Label, Evidence = b.Snippet, TimeType = "History DB last modified", Severity = b.Severity, Confidence = b.Confidence });
            foreach (var p in sourceProjects.Take(50)) events.Add(new CheatingTimelineEvent { When = LatestSampleTime(p.Samples), EventType = "Source/build group", Source = "File system grouping", Summary = p.Determination, Evidence = p.Root, TimeType = "Latest sample last write time", Severity = p.MaxSeverity, Confidence = p.MaxConfidence });
            events.Sort((a, b) => string.Compare(b.When, a.When, StringComparison.OrdinalIgnoreCase));
            return events.Take(500).ToList();
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

        private static string BuildSummaryText(ScanReport report, List<HardwareRecord> hardwareRecords, List<DeviceConnectionRecord> deviceRecords, List<FileNameMatch> fileMatches, List<BrowserHistoryMatch> browserMatches, List<BrowserHistorySource> browserHistorySources, List<ExecutionArtifact> executionArtifacts, List<BrowserDownloadMatch> browserDownloadMatches, List<RuntimeArtifact> runtimeArtifacts, List<SourceProjectSummary> sourceProjects, List<CheatingTimelineEvent> cheatingTimeline, string outputDirectory, string htmlPath, string jsonPath, string redactedHtmlPath, string redactedJsonPath, string redactedManifestPath, ReportIntegrityContext integrity)
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
            sb.AppendLine("Detected flags: " + report.Findings.Count + " total | Critical: " + report.Findings.Count(f => f.Severity == Severity.Critical) + " | High: " + report.Findings.Count(f => f.Severity == Severity.High) + " | Medium: " + report.Findings.Count(f => f.Severity == Severity.Medium));
            sb.AppendLine("Hardware records: " + hardwareRecords.Count);
            sb.AppendLine("External USB devices: " + deviceRecords.Count);
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

        private static FileNameRule AdjustRuleForEvidenceContext(FileNameRule rule, string evidenceValue, string evidenceKind)
        {
            if (rule == null) return null;

            string value = ScannerHelpers.ToLowerSafe(evidenceValue);
            string token = ScannerHelpers.ToLowerSafe(rule.Token);
            string label = NormalizeDetectionLabel(rule.Label);
            bool isBrowser = evidenceKind == "BrowserHistory" || evidenceKind == "BrowserSource" || evidenceKind == "BrowserDownloadLocal";
            bool isUsageTrace = evidenceKind == "ExecutionPrefetch" || evidenceKind == "ExecutionAmCache" || evidenceKind == "RuntimeProcess" || evidenceKind == "RuntimeService" || evidenceKind == "StartupRegistry" || evidenceKind == "ScheduledTask";
            bool isLocalDownload = evidenceKind == "BrowserDownloadLocal";
            bool hasStrongContext = ContainsStrongCheatContext(value);
            bool broad = IsBroadWeakToken(token) || IsBroadRuleLabel(rule.Label);

            if (IsKnownBenignContextMatch(value, token, evidenceKind, hasStrongContext, broad)) return null;

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

            if (IsContextSensitiveSingleWord(token) && !hasStrongContext)
            {
                if (isBrowser && !isLocalDownload) return null;
                confidence = Math.Min(confidence, 50);
                score = Math.Min(score, 6);
                severity = Severity.Low;
                label = "Context-needed keyword hit";
            }

            if (isBrowser && !hasStrongContext && IsShortOrRiskyToken(token))
            {
                return null;
            }

            if (isUsageTrace)
            {
                if (IsStrongUsageToken(token) || hasStrongContext)
                {
                    confidence = Math.Min(96, confidence + 8);
                    score = Math.Min(90, score + (evidenceKind == "ExecutionPrefetch" ? 18 : 12));
                    if (severity < Severity.High && IsStrongUsageToken(token)) severity = Severity.High;
                    label = NormalizeUsageLabel(label, token);
                }
                else if (broad)
                {
                    confidence = Math.Min(confidence, 48);
                    score = Math.Min(score, 4);
                    severity = Severity.Low;
                }
            }

            if (evidenceKind == "FileName" && IsHighTrustUserEvidencePath(value) && hasStrongContext)
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

        private static bool IsKnownBenignContextMatch(string value, string token, string evidenceKind, bool hasStrongContext, bool broad)
        {
            if (string.IsNullOrWhiteSpace(value)) return false;

            if (IsNormalFrameworkOrVendorPath(value, token) && !hasStrongContext) return true;

            if ((evidenceKind == "RuntimeService" || evidenceKind == "RuntimeProcess") && IsNormalWindowsOrVendorRuntime(value, token) && !hasStrongContext) return true;

            if ((evidenceKind == "FileName" || evidenceKind == "BrowserDownloadLocal") && IsNormalFrameworkBinary(value, token) && !hasStrongContext) return true;

            if (evidenceKind == "Installed")
            {
                if (value.Contains("microsoft .net host fx resolver") || value.Contains("microsoft .net host") || value.Contains("windows desktop runtime")) return true;
                if (IsVeryBroadWeakToken(token) && !hasStrongContext) return true;
            }

            if ((evidenceKind == "BrowserHistory" || evidenceKind == "BrowserSource") && broad && !hasStrongContext) return true;

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
            string[] tokens = { "cheat", "hack", "hacks", "trainer", "modmenu", "mod-menu", "executor", "exploit", "overlay", "paste", "crack", "offsets", "netvars", "signatures", "patternscan", "sigscan", "w2s", "rpm", "wpm", "r0", "r3", "eac", "battleye", "vanguard", "faceit", "ricochet", "vgk", "vgc", "dse", "patchguard", "unban", "spoof", "serials", "slotted", "external", "internal", "menu", "driver", "sdk", "dump", "dumper", "trace", "traces", "private", "invite", "auth", "panel", "source", "client dll", "resolver", "loader.dll" };
            return tokens.Any(t => string.Equals(t, token, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsVeryBroadWeakToken(string token)
        {
            string[] tokens = { "external", "internal", "menu", "driver", "sdk", "dump", "dumper", "trace", "traces", "private", "invite", "auth", "panel", "source", "client dll", "resolver", "loader.dll", "overlay" };
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

        private static string NormalizeUsageLabel(string label, string token)
        {
            string lower = ScannerHelpers.ToLowerSafe(label + " " + token);
            if (lower.Contains("inject")) return "Injector launch trace";
            if (lower.Contains("mapper") || lower.Contains("kdmapper") || lower.Contains("driver mapper")) return "Driver mapper launch trace";
            if (lower.Contains("loader")) return "Cheat loader launch trace";
            if (lower.Contains("spoofer") || lower.Contains("hwid")) return "Spoofer launch trace";
            if (lower.Contains("bypass")) return "Anti-cheat bypass launch trace";
            if (lower.Contains("aimbot") || lower.Contains("triggerbot") || lower.Contains("esp") || lower.Contains("radar")) return "Cheat feature launch trace";
            return label;
        }

        private static FileNameRule BestRuleMatch(string value, List<FileNameRule> rules)
        {
            FileNameRule best = null;
            foreach (var rule in rules)
            {
                if (!ScannerHelpers.RuleMatchesLoose(value, rule.Token)) continue;
                if (best == null || rule.Score > best.Score || (rule.Score == best.Score && rule.Confidence > best.Confidence) || (rule.Score == best.Score && rule.Confidence == best.Confidence && rule.Severity > best.Severity)) best = rule;
            }
            return best;
        }

        private static IEnumerable<string> SafeEnumerateFiles(string dir, string pattern, SearchOption option)
        {
            try { return Directory.EnumerateFiles(dir, pattern, option).ToList(); }
            catch { return new string[0]; }
        }

        private static IEnumerable<string> SafeEnumerateDirectories(string dir)
        {
            try { return Directory.EnumerateDirectories(dir).ToList(); }
            catch { return new string[0]; }
        }

        private static string ReadBinaryAsText(string path, int maxBytes)
        {
            try
            {
                byte[] bytes;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    int length = (int)Math.Min(fs.Length, maxBytes);
                    bytes = new byte[length];
                    fs.ReadExactly(bytes, 0, length);
                }
                var ascii = new StringBuilder(bytes.Length);
                foreach (byte b in bytes) ascii.Append(b >= 32 && b <= 126 ? (char)b : ' ');
                return ascii.ToString();
            }
            catch { return ""; }
        }

        private static string Snippet(string data, int pos, int tokenLength)
        {
            int start = Math.Max(0, pos - 140);
            int end = Math.Min(data.Length, pos + Math.Max(tokenLength, 1) + 180);
            return data.Substring(start, end - start);
        }

        private static string ExtractBestUrl(string text, string token)
        {
            foreach (Match m in Regex.Matches(text ?? "", "https?://[^\\s<>\"']+", RegexOptions.IgnoreCase))
            {
                string url = CleanUrlCandidate(m.Value);
                if (string.IsNullOrWhiteSpace(token) || url.IndexOf(token.Replace(" ", ""), StringComparison.OrdinalIgnoreCase) >= 0 || url.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0) return url;
            }
            var first = Regex.Match(text ?? "", "https?://[^\\s<>\"']+", RegexOptions.IgnoreCase);
            return first.Success ? CleanUrlCandidate(first.Value) : "";
        }

        private static string CleanUrlCandidate(string url)
        {
            return (url ?? "").Trim().TrimEnd('.', ',', ';', ')', ']', '}', '"', '\'', '\0');
        }

        private static string DomainFromUrl(string url)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(url)) return "";
                return new Uri(url).Host;
            }
            catch { return ""; }
        }

        private static string ExtractFirstWindowsPath(string text)
        {
            var m = Regex.Match(text ?? "", "[A-Za-z]:\\\\[^\\s<>\"']+", RegexOptions.IgnoreCase);
            return m.Success ? m.Value.TrimEnd('.', ',', ';', ')', ']', '}', '"', '\'', '\0') : "";
        }
    }
}
