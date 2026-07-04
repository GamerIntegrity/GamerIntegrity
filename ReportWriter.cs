using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace GamerIntegrity
{
    public static class ReportWriter
    {
        public static ScoreAssessment CalculateScoreAssessment(ScanReport report)
        {
            var assessment = new ScoreAssessment { RawEvidencePoints = report.RawScore };
            var positive = report.Findings.Where(f => f.Score > 0).ToList();
            foreach (var group in positive.GroupBy(f => f.Category))
            {
                double raw = group.Sum(f => f.Score * SeverityScoreMultiplier(f.Severity));
                double cap = CategoryScoreCap(group.Key);
                double adjusted = Math.Min(cap, raw);
                var strongest = group.OrderByDescending(f => f.Score).ThenByDescending(f => f.Confidence).First();
                assessment.Categories.Add(new CategoryScoreBreakdown
                {
                    Category = group.Key,
                    RawPoints = raw,
                    AdjustedPoints = adjusted,
                    FindingCount = group.Count(),
                    MaxSeverity = group.Max(f => f.Severity),
                    MaxConfidence = group.Max(f => f.Confidence),
                    StrongestFinding = strongest.Title
                });
            }

            double adjustedTotal = assessment.Categories.Sum(c => c.AdjustedPoints);
            assessment.NormalizedScore = ScannerHelpers.Clamp((int)Math.Round(100.0 * (1.0 - Math.Exp(-adjustedTotal / 150.0))), 0, 100);
            assessment.ReportConfidence = positive.Count == 0 ? 55 : ScannerHelpers.Clamp((int)Math.Round(positive.Average(f => f.Confidence) + Math.Min(20, positive.Count * 1.5)), 0, 100);
            if (assessment.NormalizedScore >= 85) assessment.ConcernLevel = "Critical concern";
            else if (assessment.NormalizedScore >= 65) assessment.ConcernLevel = "High concern";
            else if (assessment.NormalizedScore >= 35) assessment.ConcernLevel = "Medium concern";
            else if (assessment.NormalizedScore >= 12) assessment.ConcernLevel = "Low concern";
            else assessment.ConcernLevel = "No strong concern";

            assessment.Categories.Sort((a, b) => b.AdjustedPoints.CompareTo(a.AdjustedPoints));
            foreach (var c in assessment.Categories.Take(6))
                assessment.TopFactors.Add(ScannerHelpers.ReportCategoryLabel(c.Category) + ": " + c.StrongestFinding + " (" + Math.Round(c.AdjustedPoints, 1).ToString(CultureInfo.InvariantCulture) + " pts)");
            assessment.Rationale = positive.Count == 0
                ? "Only informational findings were recorded. No local indicator category contributed positive evidence points."
                : "Score is calibrated from positive local evidence categories with caps to avoid one noisy source overwhelming the report.";
            return assessment;
        }

        private static double SeverityScoreMultiplier(Severity severity)
        {
            switch (severity)
            {
                case Severity.Critical: return 1.35;
                case Severity.High: return 1.15;
                case Severity.Medium: return 1.0;
                case Severity.Low: return 0.7;
                default: return 0.0;
            }
        }

        private static double CategoryScoreCap(string category)
        {
            switch (category)
            {
                case "Source Projects": return 95;
                case "Execution Evidence": return 90;
                case "Browser Source/Download Evidence": return 85;
                case "File Name Scan": return 75;
                case "Browser History": return 70;
                case "Runtime/Startup": return 70;
                case "Installed Programs": return 55;
                case "Drivers": return 55;
                case "Boot Security": return 45;
                case "Hardware Identity": return 40;
                default: return 30;
            }
        }

        public static VerdictAssessment BuildVerdict(ScanReport report, ScoreAssessment assessment, List<FileNameMatch> fileMatches, List<BrowserHistoryMatch> browserMatches, List<ExecutionArtifact> executionArtifacts, List<BrowserDownloadMatch> browserDownloadMatches, List<RuntimeArtifact> runtimeArtifacts, List<SourceProjectSummary> sourceProjects)
        {
            int strongSource = sourceProjects.Count(p => p.DirectSourceCount > 0 && p.GeneratedStructure);
            int execution = executionArtifacts.Count(a => a.Severity >= Severity.High);
            int browserDownloads = browserDownloadMatches.Count(d => d.Severity >= Severity.High);
            int runtime = runtimeArtifacts.Count(r => r.Severity >= Severity.High);

            var verdict = new VerdictAssessment();
            if (assessment.NormalizedScore >= 85 || strongSource > 0 && (execution > 0 || browserDownloads > 0 || runtime > 0))
            {
                verdict.Label = "Strong cheat/tool evidence present";
                verdict.Level = "critical";
                verdict.Summary = "Multiple high-value local evidence categories matched cheat, mapper, injector, spoofer, source, or build indicators.";
                verdict.Basis = "Source/build groups: " + sourceProjects.Count + ", execution traces: " + executionArtifacts.Count + ", browser source/download records: " + browserDownloadMatches.Count + ", runtime/startup artifacts: " + runtimeArtifacts.Count + ".";
                verdict.Recommendation = "Check projects, launch traces, downloads, and startup artifacts first.";
            }
            else if (assessment.NormalizedScore >= 65)
            {
                verdict.Label = "High concern evidence";
                verdict.Level = "high";
                verdict.Summary = "High-confidence local indicators were found, but the results should still be checked in context.";
                verdict.Basis = "Evidence strength " + assessment.NormalizedScore + "/100 with " + report.Findings.Count(f => f.Score > 0) + " positive finding category result(s).";
                verdict.Recommendation = "Check the highest-scoring categories and keep exported files together.";
            }
            else if (assessment.NormalizedScore >= 35)
            {
                verdict.Label = "Needs staff attention";
                verdict.Level = "medium";
                verdict.Summary = "Some local indicators were found. These may include legitimate developer or reverse-engineering tools, so context matters.";
                verdict.Basis = "Evidence strength " + assessment.NormalizedScore + "/100.";
                verdict.Recommendation = "Check whether the findings are legitimate tools, old artifacts, or directly tied to cheat software.";
            }
            else if (assessment.NormalizedScore >= 12)
            {
                verdict.Label = "Low-level indicators found";
                verdict.Level = "low";
                verdict.Summary = "Only low or limited indicators were found.";
                verdict.Basis = "Evidence strength " + assessment.NormalizedScore + "/100.";
                verdict.Recommendation = "Check only if other context makes the system suspicious.";
            }
            else
            {
                verdict.Label = "No strong cheat evidence found";
                verdict.Level = "clean";
                verdict.Summary = "No positive local indicator categories contributed meaningful evidence points.";
                verdict.Basis = "Evidence strength " + assessment.NormalizedScore + "/100.";
                verdict.Recommendation = "No immediate action from this report alone.";
            }
            return verdict;
        }

        public static bool WriteJsonReport(ScanReport report, List<DriverInfo> drivers, List<HardwareRecord> hardwareRecords, List<DeviceConnectionRecord> deviceRecords, List<FileNameMatch> installedProgramMatches, List<FileNameMatch> fileMatches, List<BrowserHistoryMatch> browserMatches, List<BrowserHistorySource> browserHistorySources, List<ExecutionArtifact> executionArtifacts, List<BrowserDownloadMatch> browserDownloadMatches, List<RuntimeArtifact> runtimeArtifacts, List<SourceProjectSummary> sourceProjects, List<CheatingTimelineEvent> cheatingTimeline, ReportIntegrityContext integrity, string path, bool redacted)
        {
            try
            {
                string content = BuildJsonReport(report, drivers, hardwareRecords, deviceRecords, installedProgramMatches, fileMatches, browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects, cheatingTimeline, integrity, redacted);
                if (string.IsNullOrEmpty(content)) return false;
                File.WriteAllText(path, content, new UTF8Encoding(false));
                return true;
            }
            catch { return false; }
        }

        public static string BuildJsonReport(ScanReport report, List<DriverInfo> drivers, List<HardwareRecord> hardwareRecords, List<DeviceConnectionRecord> deviceRecords, List<FileNameMatch> installedProgramMatches, List<FileNameMatch> fileMatches, List<BrowserHistoryMatch> browserMatches, List<BrowserHistorySource> browserHistorySources, List<ExecutionArtifact> executionArtifacts, List<BrowserDownloadMatch> browserDownloadMatches, List<RuntimeArtifact> runtimeArtifacts, List<SourceProjectSummary> sourceProjects, List<CheatingTimelineEvent> cheatingTimeline, ReportIntegrityContext integrity, bool redacted)
        {
            try
            {
                var assessment = CalculateScoreAssessment(report);
                var verdict = BuildVerdict(report, assessment, fileMatches, browserMatches, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects);
                var r = new Redactor(integrity, redacted);
                var sb = new StringBuilder(1024 * 256);
                sb.AppendLine("{");
                Prop(sb, 1, "tool", "GamerIntegrity", true);
                Prop(sb, 1, "reportVersion", ScannerHelpers.ReleaseVersion, true);
                Prop(sb, 1, "evidenceModelVersion", ScannerHelpers.EvidenceModelVersion, true);
                Prop(sb, 1, "redacted", redacted, true);
                sb.Append(Indent(1)).AppendLine("\"integrity\": {");
                Prop(sb, 2, "reportId", integrity.ReportId, true);
                Prop(sb, 2, "scanStartTime", integrity.ScanStartTime, true);
                Prop(sb, 2, "scanEndTime", integrity.ScanEndTime, true);
                Prop(sb, 2, "computerName", r.Text(integrity.ComputerName), true);
                Prop(sb, 2, "userName", r.Text(integrity.UserName), true);
                Prop(sb, 2, "scannerVersion", integrity.ScannerVersion, false);
                sb.Append(Indent(1)).AppendLine("},");

                sb.Append(Indent(1)).AppendLine("\"summary\": {");
                Prop(sb, 2, "verdict", verdict.Label, true);
                Prop(sb, 2, "verdictLevel", verdict.Level, true);
                Prop(sb, 2, "verdictBasis", verdict.Basis, true);
                Prop(sb, 2, "overallConcern", assessment.ConcernLevel, true);
                Prop(sb, 2, "evidenceStrength", assessment.NormalizedScore, true);
                Prop(sb, 2, "scanConfidence", assessment.ReportConfidence, true);
                Prop(sb, 2, "rawSignalPoints", report.RawScore, true);
                Prop(sb, 2, "findingCount", report.Findings.Count, true);
                Prop(sb, 2, "fileNameMatches", fileMatches.Count, true);
                Prop(sb, 2, "browserKeywordMatches", browserMatches.Count, true);
                Prop(sb, 2, "browserSourceDownloadMatches", browserDownloadMatches.Count, true);
                Prop(sb, 2, "executionArtifacts", executionArtifacts.Count, true);
                Prop(sb, 2, "runtimeArtifacts", runtimeArtifacts.Count, true);
                Prop(sb, 2, "sourceProjectGroups", sourceProjects.Count, false);
                sb.Append(Indent(1)).AppendLine("},");

                WriteFindingsJson(sb, report.Findings, r, true);
                WriteFileMatchesJson(sb, "installedProgramMatches", installedProgramMatches, r, true);
                WriteFileMatchesJson(sb, "fileNameMatches", fileMatches, r, true);
                WriteBrowserMatchesJson(sb, browserMatches, r, true);
                WriteBrowserSourcesJson(sb, browserHistorySources, r, true);
                WriteExecutionJson(sb, executionArtifacts, r, true);
                WriteBrowserDownloadsJson(sb, browserDownloadMatches, r, true);
                WriteRuntimeJson(sb, runtimeArtifacts, r, true);
                WriteSourceProjectsJson(sb, sourceProjects, r, true);
                WriteTimelineJson(sb, cheatingTimeline, r, true);
                WriteDriversJson(sb, drivers, r, true);
                WriteHardwareJson(sb, hardwareRecords, r, true);
                WriteDevicesJson(sb, deviceRecords, r, false);
                sb.AppendLine("}");
                return sb.ToString();
            }
            catch { return string.Empty; }
        }

        public static bool WriteHtmlReport(ScanReport report, List<DriverInfo> drivers, List<HardwareRecord> hardwareRecords, List<DeviceConnectionRecord> deviceRecords, List<FileNameMatch> installedProgramMatches, List<FileNameMatch> fileMatches, List<BrowserHistoryMatch> browserMatches, List<BrowserHistorySource> browserHistorySources, List<ExecutionArtifact> executionArtifacts, List<BrowserDownloadMatch> browserDownloadMatches, List<RuntimeArtifact> runtimeArtifacts, List<SourceProjectSummary> sourceProjects, List<CheatingTimelineEvent> cheatingTimeline, ReportIntegrityContext integrity, string path, bool redacted)
        {
            try
            {
                string content = BuildHtmlReport(report, drivers, hardwareRecords, deviceRecords, installedProgramMatches, fileMatches, browserMatches, browserHistorySources, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects, cheatingTimeline, integrity, redacted);
                if (string.IsNullOrEmpty(content)) return false;
                File.WriteAllText(path, content, new UTF8Encoding(false));
                return true;
            }
            catch { return false; }
        }

        public static string BuildHtmlReport(ScanReport report, List<DriverInfo> drivers, List<HardwareRecord> hardwareRecords, List<DeviceConnectionRecord> deviceRecords, List<FileNameMatch> installedProgramMatches, List<FileNameMatch> fileMatches, List<BrowserHistoryMatch> browserMatches, List<BrowserHistorySource> browserHistorySources, List<ExecutionArtifact> executionArtifacts, List<BrowserDownloadMatch> browserDownloadMatches, List<RuntimeArtifact> runtimeArtifacts, List<SourceProjectSummary> sourceProjects, List<CheatingTimelineEvent> cheatingTimeline, ReportIntegrityContext integrity, bool redacted)
        {
            try
            {
                var assessment = CalculateScoreAssessment(report);
                var verdict = BuildVerdict(report, assessment, fileMatches, browserMatches, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects);
                var r = new Redactor(integrity, redacted);
                var ordered = report.Findings
                    .OrderByDescending(f => f.Score)
                    .ThenByDescending(f => f.Severity)
                    .ToList();
                var severityCounts = report.Findings
                    .GroupBy(f => f.Severity)
                    .ToDictionary(g => g.Key, g => g.Count());
                int criticalCount = GetSeverityCount(severityCounts, Severity.Critical);
                int highCount = GetSeverityCount(severityCounts, Severity.High);
                int mediumCount = GetSeverityCount(severityCounts, Severity.Medium);
                int nonWindowsDrivers = drivers.Count(d => !d.WindowsSystemPath);
                int untrustedNonWindowsDrivers = drivers.Count(d => !d.WindowsSystemPath && d.FileExists && !d.SignedTrusted);
                string summaryText = BuildSummaryText(report, installedProgramMatches, fileMatches, browserMatches, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects);
                var caseSummaryItems = BuildCaseSummaryItems(fileMatches, browserMatches, executionArtifacts, browserDownloadMatches, runtimeArtifacts, sourceProjects);

                var sb = new StringBuilder(1024 * 768);
                sb.AppendLine("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
                sb.AppendLine("<title>GamerIntegrity Report</title>");
                sb.AppendLine("<style>");
                sb.AppendLine(Css());
                sb.AppendLine("</style></head><body><div class=\"wrapper\">");

                string subtitle = string.IsNullOrWhiteSpace(integrity.ComputerName) ? "Local PC report" : r.Text(integrity.ComputerName);
                sb.AppendLine("<div class=\"wiki-topbar\"><div class=\"wiki-topbar-inner\"><div class=\"wiki-brand\"><div class=\"wiki-title\">GamerIntegrity Report</div><div class=\"wiki-subtitle\">" + H(subtitle) + "</div></div><div class=\"wiki-search\"><input id=\"wikiSearch\" type=\"search\" placeholder=\"Search report: detections, paths, tools, hashes, timestamps...\" autocomplete=\"off\"></div></div></div>");
                sb.AppendLine("<div class=\"wiki-layout\"><aside class=\"wiki-sidebar\"><div class=\"wiki-sidebar-title\">Table of Contents</div>");
                sb.AppendLine("<a href=\"#determination\">Overview</a><a href=\"#case-summary\">Summary</a><a href=\"#scan-totals\">Scan Totals</a><a href=\"#timeline\">Timeline</a><a href=\"#scoring\">Scoring</a><a href=\"#findings\">Detections</a><a href=\"#drivers\">Drivers</a><a href=\"#hardware\">Hardware</a><a href=\"#usb\">External Devices</a><a href=\"#software-source\">Projects</a><a href=\"#execution\">Launch</a><a href=\"#browser-source-download\">Downloads</a><a href=\"#runtime\">Startup</a><a href=\"#installed-programs\">Reversal</a><a href=\"#browser-keywords\">Browser</a><a href=\"#file-names\">Files / Folders</a>");
                sb.AppendLine("</aside><main class=\"wiki-main\"><div id=\"noSearchResults\" class=\"no-search-results\">No visible report rows matched the search.</div>");

                if (redacted)
                    sb.AppendLine("<div class=\"notice redaction-banner search-item\"><strong>Redacted export:</strong> identity fields, local user paths, hardware serials, MAC addresses, USB serial portions, and report-folder paths have been masked for sharing.</div>");

                sb.AppendLine("<section id=\"determination\" class=\"wiki-section\" style=\"margin-top:0\"><div class=\"verdict " + ScannerHelpers.VerdictCssClass(verdict.Level) + " search-item\"><div class=\"metric-label\">Overview</div><div class=\"verdict-title\">" + H(verdict.Label) + "</div><div class=\"verdict-summary\">" + H(verdict.Summary) + "</div><div class=\"small\" style=\"margin-top:10px\"><strong>Basis:</strong> " + H(verdict.Basis) + "</div></div></section>");

                sb.AppendLine("<section id=\"case-summary\" class=\"wiki-section\"><h2>Summary</h2>");
                sb.AppendLine("<div class=\"notice search-item\"><strong>Summary:</strong> " + H(summaryText) + "</div>");
                sb.AppendLine("<div class=\"card search-item\" style=\"margin-top:12px\"><div class=\"metric-label\">Check first</div><ol style=\"margin:8px 0 0 20px; padding:0\">");
                foreach (var item in caseSummaryItems)
                    sb.AppendLine("<li style=\"margin:6px 0\">" + H(item) + "</li>");
                sb.AppendLine("</ol></div></section>");

                sb.AppendLine("<div class=\"grid\">");
                AppendMetricCard(sb, "Overall level", "<span class=\"badge " + ScannerHelpers.ConcernCssClass(assessment.ConcernLevel) + "\">" + H(assessment.ConcernLevel) + "</span>", "");
                AppendMetricCard(sb, "Evidence strength", assessment.NormalizedScore + "<span class=\"small\"> / 100</span>", "Based on detected evidence");
                AppendMetricCard(sb, "Scan confidence", assessment.ReportConfidence + "%", "Confidence in this scan result");
                AppendMetricCard(sb, "Points", report.RawScore.ToString(CultureInfo.InvariantCulture), "Uncapped internal value");
                AppendMetricCard(sb, "Detections", report.Findings.Count.ToString(CultureInfo.InvariantCulture), "");
                AppendMetricCard(sb, "Generated", H(ScannerHelpers.CurrentLocalDisplayTimestamp()), "", "font-size:16px");
                sb.AppendLine("</div>");

                sb.AppendLine("<section id=\"scan-totals\" class=\"wiki-section\"><h2>Scan totals</h2><div class=\"grid\">");
                AppendMetricCard(sb, "Critical findings", criticalCount.ToString(CultureInfo.InvariantCulture), "");
                AppendMetricCard(sb, "High findings", highCount.ToString(CultureInfo.InvariantCulture), "");
                AppendMetricCard(sb, "Medium findings", mediumCount.ToString(CultureInfo.InvariantCulture), "");
                AppendMetricCard(sb, "Non-Windows loaded drivers", nonWindowsDrivers.ToString(CultureInfo.InvariantCulture), "Untrusted: " + untrustedNonWindowsDrivers);
                AppendMetricCard(sb, "Hardware identity records", hardwareRecords.Count.ToString(CultureInfo.InvariantCulture), "SMBIOS / disks / MACs");
                AppendMetricCard(sb, "External USB devices", deviceRecords.Count.ToString(CultureInfo.InvariantCulture), "USB / USB storage history");
                AppendMetricCard(sb, "File/folder name matches", fileMatches.Count.ToString(CultureInfo.InvariantCulture), "Names only");
                AppendMetricCard(sb, "Detected browser profiles", browserHistorySources.Count.ToString(CultureInfo.InvariantCulture), "Profiles/stores");
                AppendMetricCard(sb, "Browser/domain matches", browserMatches.Count.ToString(CultureInfo.InvariantCulture), "Matching snippets only");
                AppendMetricCard(sb, "Browser source/download matches", browserDownloadMatches.Count.ToString(CultureInfo.InvariantCulture), "Source/download records");
                AppendMetricCard(sb, "Execution traces", executionArtifacts.Count.ToString(CultureInfo.InvariantCulture), "AmCache / Prefetch");
                AppendMetricCard(sb, "Runtime/startup artifacts", runtimeArtifacts.Count.ToString(CultureInfo.InvariantCulture), "Processes / services / tasks");
                AppendMetricCard(sb, "Source project groups", sourceProjects.Count.ToString(CultureInfo.InvariantCulture), "Grouped source/build projects");
                sb.AppendLine("</div></section>");

                WriteTimelineHtml(sb, cheatingTimeline, r);
                WriteScoreBreakdownHtml(sb, assessment);
                WriteFindingsHtml(sb, ordered, r);
                WriteDriversHtml(sb, drivers, r);
                WriteHardwareHtml(sb, hardwareRecords, r);
                WriteDevicesHtml(sb, deviceRecords, r);
                WriteSourceProjectsHtml(sb, sourceProjects, r);
                WriteExecutionHtml(sb, executionArtifacts, r);
                WriteBrowserDownloadsHtml(sb, browserDownloadMatches, r);
                WriteRuntimeHtml(sb, runtimeArtifacts, r);
                WriteInstalledProgramsHtml(sb, installedProgramMatches, r);
                WriteBrowserHtml(sb, browserMatches, browserHistorySources, r);
                WriteFileMatchesHtml(sb, fileMatches, r);

                sb.AppendLine("<div class=\"footer\">Generated by GamerIntegrity v1. Keep the JSON report and integrity manifest with this HTML report when you need machine-readable scan data.</div>");
                sb.AppendLine(SearchScript());
                sb.AppendLine("</main></div></div></body></html>");

                return sb.ToString();
            }
            catch { return string.Empty; }
        }

        public static bool WriteReportIntegrityManifest(ReportIntegrityContext ctx, string htmlPath, string jsonPath, string manifestPath, bool redacted)
        {
            try
            {
                if (ctx != null) ctx.ManifestPath = manifestPath;
                string content = BuildReportIntegrityManifestContent(ctx, htmlPath, jsonPath, redacted);
                if (string.IsNullOrEmpty(content)) return false;
                File.WriteAllText(manifestPath, content, new UTF8Encoding(false));
                return true;
            }
            catch { return false; }
        }

        public static string BuildReportIntegrityManifestContent(ReportIntegrityContext ctx, string htmlPath, string jsonPath, bool redacted)
        {
            try
            {
                var r = new Redactor(ctx, redacted);
                string htmlHash = ScannerHelpers.Sha256File(htmlPath);
                string jsonHash = ScannerHelpers.Sha256File(jsonPath);
                var sb = new StringBuilder();
                sb.AppendLine("{");
                Prop(sb, 1, "tool", "GamerIntegrity", true);
                Prop(sb, 1, "manifestVersion", ScannerHelpers.ReleaseVersion, true);
                Prop(sb, 1, "reportId", ctx.ReportId, true);
                Prop(sb, 1, "scannerVersion", ctx.ScannerVersion, true);
                Prop(sb, 1, "scanStartTime", ctx.ScanStartTime, true);
                Prop(sb, 1, "scanEndTime", ctx.ScanEndTime, true);
                Prop(sb, 1, "computerName", r.Text(ctx.ComputerName), true);
                Prop(sb, 1, "userName", r.Text(ctx.UserName), true);
                Prop(sb, 1, "hashAlgorithm", "SHA-256", true);
                sb.Append(Indent(1)).AppendLine("\"files\": [");
                sb.Append(Indent(2)).Append("{\"type\": \"HTML report\", \"path\": \"").Append(J(r.Path(htmlPath))).Append("\", \"sha256\": \"").Append(J(htmlHash)).AppendLine("\"},");
                sb.Append(Indent(2)).Append("{\"type\": \"JSON report\", \"path\": \"").Append(J(r.Path(jsonPath))).Append("\", \"sha256\": \"").Append(J(jsonHash)).AppendLine("\"}");
                sb.Append(Indent(1)).AppendLine("],");
                Prop(sb, 1, "note", "This manifest is written after the HTML and JSON reports are created. Preserve this manifest with both reports to verify report integrity.", false);
                sb.AppendLine("}");
                return sb.ToString();
            }
            catch { return string.Empty; }
        }

        private static void WriteFindingsJson(StringBuilder sb, List<Finding> findings, Redactor r, bool comma)
        {
            sb.Append(Indent(1)).AppendLine("\"findings\": [");
            for (int i = 0; i < findings.Count; i++)
            {
                var f = findings[i];
                sb.Append(Indent(2)).AppendLine("{");
                Prop(sb, 3, "category", f.Category, true);
                Prop(sb, 3, "categoryLabel", ScannerHelpers.ReportCategoryLabel(f.Category), true);
                Prop(sb, 3, "title", f.Title, true);
                Prop(sb, 3, "details", r.Text(f.Details), true);
                Prop(sb, 3, "severity", f.Severity.ToString(), true);
                Prop(sb, 3, "confidence", f.Confidence, true);
                Prop(sb, 3, "score", f.Score, false);
                sb.Append(Indent(2)).Append("}").AppendLine(i + 1 < findings.Count ? "," : "");
            }
            sb.Append(Indent(1)).Append("]").AppendLine(comma ? "," : "");
        }

        private static void WriteFileMatchesJson(StringBuilder sb, string name, List<FileNameMatch> matches, Redactor r, bool comma)
        {
            sb.Append(Indent(1)).Append("\"").Append(name).AppendLine("\": [");
            for (int i = 0; i < matches.Count; i++)
            {
                var m = matches[i];
                sb.Append(Indent(2)).AppendLine("{");
                Prop(sb, 3, "path", r.Path(m.Path), true);
                Prop(sb, 3, "token", m.Token, true);
                Prop(sb, 3, "label", m.Label, true);
                Prop(sb, 3, "severity", m.Severity.ToString(), true);
                Prop(sb, 3, "confidence", m.Confidence, true);
                Prop(sb, 3, "score", m.Score, true);
                Prop(sb, 3, "lastWriteTime", m.LastWriteTime, false);
                sb.Append(Indent(2)).Append("}").AppendLine(i + 1 < matches.Count ? "," : "");
            }
            sb.Append(Indent(1)).Append("]").AppendLine(comma ? "," : "");
        }

        private static void WriteBrowserMatchesJson(StringBuilder sb, List<BrowserHistoryMatch> matches, Redactor r, bool comma)
        {
            sb.Append(Indent(1)).AppendLine("\"browserKeywordMatches\": [");
            for (int i = 0; i < matches.Count; i++)
            {
                var m = matches[i];
                sb.Append(Indent(2)).AppendLine("{");
                Prop(sb, 3, "browser", m.Browser, true);
                Prop(sb, 3, "profile", m.Profile, true);
                Prop(sb, 3, "historyPath", r.Path(m.HistoryPath), true);
                Prop(sb, 3, "token", m.Token, true);
                Prop(sb, 3, "label", m.Label, true);
                Prop(sb, 3, "snippet", r.Text(m.Snippet), true);
                Prop(sb, 3, "severity", m.Severity.ToString(), true);
                Prop(sb, 3, "confidence", m.Confidence, true);
                Prop(sb, 3, "score", m.Score, false);
                sb.Append(Indent(2)).Append("}").AppendLine(i + 1 < matches.Count ? "," : "");
            }
            sb.Append(Indent(1)).Append("]").AppendLine(comma ? "," : "");
        }

        private static void WriteBrowserSourcesJson(StringBuilder sb, List<BrowserHistorySource> sources, Redactor r, bool comma)
        {
            sb.Append(Indent(1)).AppendLine("\"browserHistorySources\": [");
            for (int i = 0; i < sources.Count; i++)
            {
                var s = sources[i];
                sb.Append(Indent(2)).Append("{\"browser\": \"").Append(J(s.Browser)).Append("\", \"profile\": \"").Append(J(s.Profile)).Append("\", \"historyPath\": \"").Append(J(r.Path(s.HistoryPath))).Append("\"}").AppendLine(i + 1 < sources.Count ? "," : "");
            }
            sb.Append(Indent(1)).Append("]").AppendLine(comma ? "," : "");
        }

        private static void WriteExecutionJson(StringBuilder sb, List<ExecutionArtifact> items, Redactor r, bool comma)
        {
            sb.Append(Indent(1)).AppendLine("\"executionArtifacts\": [");
            for (int i = 0; i < items.Count; i++)
            {
                var m = items[i];
                sb.Append(Indent(2)).AppendLine("{");
                Prop(sb, 3, "source", m.Source, true);
                Prop(sb, 3, "name", m.Name, true);
                Prop(sb, 3, "path", r.Path(m.Path), true);
                Prop(sb, 3, "token", m.Token, true);
                Prop(sb, 3, "label", m.Label, true);
                Prop(sb, 3, "when", m.When, true);
                Prop(sb, 3, "details", r.Text(m.Details), true);
                Prop(sb, 3, "severity", m.Severity.ToString(), true);
                Prop(sb, 3, "confidence", m.Confidence, true);
                Prop(sb, 3, "score", m.Score, false);
                sb.Append(Indent(2)).Append("}").AppendLine(i + 1 < items.Count ? "," : "");
            }
            sb.Append(Indent(1)).Append("]").AppendLine(comma ? "," : "");
        }

        private static void WriteBrowserDownloadsJson(StringBuilder sb, List<BrowserDownloadMatch> items, Redactor r, bool comma)
        {
            sb.Append(Indent(1)).AppendLine("\"browserSourceDownloadMatches\": [");
            for (int i = 0; i < items.Count; i++)
            {
                var m = items[i];
                sb.Append(Indent(2)).AppendLine("{");
                Prop(sb, 3, "browser", m.Browser, true);
                Prop(sb, 3, "profile", m.Profile, true);
                Prop(sb, 3, "historyPath", r.Path(m.HistoryPath), true);
                Prop(sb, 3, "token", m.Token, true);
                Prop(sb, 3, "label", m.Label, true);
                Prop(sb, 3, "url", r.Text(m.Url), true);
                Prop(sb, 3, "domain", m.Domain, true);
                Prop(sb, 3, "localPath", r.Path(m.LocalPath), true);
                Prop(sb, 3, "evidenceType", m.EvidenceType, true);
                Prop(sb, 3, "snippet", r.Text(m.Snippet), true);
                Prop(sb, 3, "when", m.When, true);
                Prop(sb, 3, "timeType", m.TimeType, true);
                Prop(sb, 3, "severity", m.Severity.ToString(), true);
                Prop(sb, 3, "confidence", m.Confidence, true);
                Prop(sb, 3, "score", m.Score, false);
                sb.Append(Indent(2)).Append("}").AppendLine(i + 1 < items.Count ? "," : "");
            }
            sb.Append(Indent(1)).Append("]").AppendLine(comma ? "," : "");
        }

        private static void WriteRuntimeJson(StringBuilder sb, List<RuntimeArtifact> items, Redactor r, bool comma)
        {
            sb.Append(Indent(1)).AppendLine("\"runtimeArtifacts\": [");
            for (int i = 0; i < items.Count; i++)
            {
                var m = items[i];
                sb.Append(Indent(2)).AppendLine("{");
                Prop(sb, 3, "sourceType", m.SourceType, true);
                Prop(sb, 3, "name", m.Name, true);
                Prop(sb, 3, "path", r.Path(m.Path), true);
                Prop(sb, 3, "token", m.Token, true);
                Prop(sb, 3, "label", m.Label, true);
                Prop(sb, 3, "details", r.Text(m.Details), true);
                Prop(sb, 3, "when", m.When, true);
                Prop(sb, 3, "severity", m.Severity.ToString(), true);
                Prop(sb, 3, "confidence", m.Confidence, true);
                Prop(sb, 3, "score", m.Score, false);
                sb.Append(Indent(2)).Append("}").AppendLine(i + 1 < items.Count ? "," : "");
            }
            sb.Append(Indent(1)).Append("]").AppendLine(comma ? "," : "");
        }

        private static void WriteSourceProjectsJson(StringBuilder sb, List<SourceProjectSummary> items, Redactor r, bool comma)
        {
            sb.Append(Indent(1)).AppendLine("\"sourceProjectGroups\": [");
            for (int i = 0; i < items.Count; i++)
            {
                var p = items[i];
                sb.Append(Indent(2)).AppendLine("{");
                Prop(sb, 3, "root", r.Path(p.Root), true);
                Prop(sb, 3, "generatedStructure", p.GeneratedStructure, true);
                Prop(sb, 3, "totalDetections", p.TotalDetections, true);
                Prop(sb, 3, "directSourceCount", p.DirectSourceCount, true);
                Prop(sb, 3, "projectFileCount", p.ProjectFileCount, true);
                Prop(sb, 3, "buildArtifactCount", p.BuildArtifactCount, true);
                Prop(sb, 3, "mapperCount", p.MapperCount, true);
                Prop(sb, 3, "injectorSpooferTraceCount", p.InjectorSpooferTraceCount, true);
                Prop(sb, 3, "maxConfidence", p.MaxConfidence, true);
                Prop(sb, 3, "maxScore", p.MaxScore, true);
                Prop(sb, 3, "maxSeverity", p.MaxSeverity.ToString(), true);
                PropArray(sb, 3, "tokens", p.Tokens, true);
                PropArray(sb, 3, "labels", p.Labels, true);
                PropArray(sb, 3, "samples", p.Samples.Select(r.Path), true);
                Prop(sb, 3, "determination", p.Determination, false);
                sb.Append(Indent(2)).Append("}").AppendLine(i + 1 < items.Count ? "," : "");
            }
            sb.Append(Indent(1)).Append("]").AppendLine(comma ? "," : "");
        }

        private static void WriteTimelineJson(StringBuilder sb, List<CheatingTimelineEvent> items, Redactor r, bool comma)
        {
            sb.Append(Indent(1)).AppendLine("\"evidenceTimeline\": [");
            for (int i = 0; i < items.Count; i++)
            {
                var e = items[i];
                sb.Append(Indent(2)).AppendLine("{");
                Prop(sb, 3, "when", e.When, true);
                Prop(sb, 3, "eventType", e.EventType, true);
                Prop(sb, 3, "source", e.Source, true);
                Prop(sb, 3, "summary", e.Summary, true);
                Prop(sb, 3, "evidence", r.Text(e.Evidence), true);
                Prop(sb, 3, "timeType", e.TimeType, true);
                Prop(sb, 3, "severity", e.Severity.ToString(), true);
                Prop(sb, 3, "confidence", e.Confidence, false);
                sb.Append(Indent(2)).Append("}").AppendLine(i + 1 < items.Count ? "," : "");
            }
            sb.Append(Indent(1)).Append("]").AppendLine(comma ? "," : "");
        }

        private static void WriteDriversJson(StringBuilder sb, List<DriverInfo> items, Redactor r, bool comma)
        {
            sb.Append(Indent(1)).AppendLine("\"drivers\": [");
            for (int i = 0; i < items.Count; i++)
            {
                var d = items[i];
                sb.Append(Indent(2)).AppendLine("{");
                Prop(sb, 3, "name", d.Name, true);
                Prop(sb, 3, "path", r.Path(d.Path), true);
                Prop(sb, 3, "company", d.Company, true);
                Prop(sb, 3, "sha256", d.Sha256, true);
                Prop(sb, 3, "fileExists", d.FileExists, true);
                Prop(sb, 3, "windowsSystemPath", d.WindowsSystemPath, true);
                Prop(sb, 3, "signed", d.SignedTrusted, true);
                Prop(sb, 3, "suspiciousNamePattern", d.SuspiciousNamePattern, false);
                sb.Append(Indent(2)).Append("}").AppendLine(i + 1 < items.Count ? "," : "");
            }
            sb.Append(Indent(1)).Append("]").AppendLine(comma ? "," : "");
        }

        private static void WriteHardwareJson(StringBuilder sb, List<HardwareRecord> items, Redactor r, bool comma)
        {
            sb.Append(Indent(1)).AppendLine("\"hardwareRecords\": [");
            for (int i = 0; i < items.Count; i++)
            {
                var h = items[i];
                sb.Append(Indent(2)).Append("{\"category\": \"").Append(J(h.Category)).Append("\", \"name\": \"").Append(J(h.Name)).Append("\", \"value\": \"").Append(J(r.Text(h.Value))).Append("\", \"source\": \"").Append(J(h.Source)).Append("\"}").AppendLine(i + 1 < items.Count ? "," : "");
            }
            sb.Append(Indent(1)).Append("]").AppendLine(comma ? "," : "");
        }

        private static void WriteDevicesJson(StringBuilder sb, List<DeviceConnectionRecord> items, Redactor r, bool comma)
        {
            sb.Append(Indent(1)).AppendLine("\"externalDevices\": [");
            for (int i = 0; i < items.Count; i++)
            {
                var d = items[i];
                sb.Append(Indent(2)).AppendLine("{");
                Prop(sb, 3, "enumerator", d.Enumerator, true);
                Prop(sb, 3, "deviceId", r.DeviceId(d.DeviceId), true);
                Prop(sb, 3, "description", r.Text(d.Description), true);
                Prop(sb, 3, "manufacturer", r.Text(d.Manufacturer), true);
                Prop(sb, 3, "service", d.Service, true);
                Prop(sb, 3, "className", d.ClassName, true);
                Prop(sb, 3, "location", r.Text(d.Location), true);
                Prop(sb, 3, "firstInstallTime", d.FirstInstallTime, true);
                Prop(sb, 3, "installTime", d.InstallTime, true);
                Prop(sb, 3, "lastArrivalTime", d.LastArrivalTime, true);
                Prop(sb, 3, "lastRemovalTime", d.LastRemovalTime, true);
                Prop(sb, 3, "bestObservedTime", DeviceRecordBestTime(d), true);
                Prop(sb, 3, "currentlyPresent", d.CurrentlyPresent, true);
                Prop(sb, 3, "massStorage", d.MassStorage, true);
                Prop(sb, 3, "source", d.Source, false);
                sb.Append(Indent(2)).Append("}").AppendLine(i + 1 < items.Count ? "," : "");
            }
            sb.Append(Indent(1)).Append("]").AppendLine(comma ? "," : "");
        }

        private static void AppendMetricCard(StringBuilder sb, string label, string valueHtml, string note, string valueStyle = null)
        {
            sb.Append("<div class=\"card search-item\"><div class=\"metric-label\">").Append(H(label)).Append("</div><div class=\"metric-value\"");
            if (!string.IsNullOrWhiteSpace(valueStyle)) sb.Append(" style=\"").Append(valueStyle).Append("\"");
            sb.Append(">").Append(valueHtml).Append("</div>");
            if (!string.IsNullOrWhiteSpace(note)) sb.Append("<div class=\"small\">").Append(H(note)).Append("</div>");
            sb.AppendLine("</div>");
        }

        private static int GetSeverityCount(Dictionary<Severity, int> severityCounts, Severity severity)
        {
            int value;
            return severityCounts.TryGetValue(severity, out value) ? value : 0;
        }

        private static void AppendEmptyRow(StringBuilder sb, int colspan, string text)
        {
            sb.Append("<tr class=\"search-item\"><td colspan=\"").Append(colspan).Append("\" class=\"small\">").Append(H(text)).AppendLine("</td></tr>");
        }

        private static void AppendSeverityBadge(StringBuilder sb, Severity severity)
        {
            sb.Append("<span class=\"badge ").Append(ScannerHelpers.SeverityCssClass(severity)).Append("\">").Append(H(severity.ToString())).Append("</span>");
        }

        private static void WriteTimelineHtml(StringBuilder sb, List<CheatingTimelineEvent> items, Redactor r)
        {
            sb.AppendLine("<section id=\"timeline\" class=\"wiki-section\"><details open><summary>Evidence timeline</summary>");
            sb.AppendLine("<p class=\"small\">Dated evidence is grouped by day and sorted newest first. Undated disk/source evidence is separated so exact timestamps are not implied.</p>");
            var datedGroups = items.Where(e => !string.IsNullOrWhiteSpace(e.When) && e.When.Length >= 10)
                .GroupBy(e => e.When.Substring(0, 10))
                .OrderByDescending(g => g.Key)
                .ToList();

            sb.AppendLine("<h3>Dated events by day</h3>");
            if (datedGroups.Count == 0)
            {
                sb.AppendLine("<div class=\"notice small search-item\">No dated evidence timeline events were produced.</div>");
            }
            else
            {
                bool firstDate = true;
                foreach (var group in datedGroups)
                {
                    sb.Append("<details").Append(firstDate ? " open" : "").Append("><summary>").Append(H(group.Key)).Append(" <span class=\"summary-meta\">").Append(group.Count()).AppendLine(" event(s)</span></summary>");
                    sb.AppendLine("<table><thead><tr><th>Time</th><th>Event</th><th>Source</th><th>Evidence</th><th>Confidence</th></tr></thead><tbody>");
                    foreach (var e in group.OrderByDescending(e => e.When))
                    {
                        sb.Append("<tr class=\"search-item\"><td class=\"mono\">").Append(H(ScannerHelpers.FriendlyTimestampText(e.When))).Append("</td><td>");
                        AppendSeverityBadge(sb, e.Severity);
                        sb.Append("<br><span class=\"finding-title\">").Append(H(e.EventType)).Append("</span></td><td>").Append(H(e.Source)).Append("</td><td><div class=\"finding-title\">").Append(H(r.Text(e.Summary))).Append("</div><div class=\"mono small\">").Append(H(r.Text(e.Evidence))).Append("</div>");
                        if (!string.IsNullOrWhiteSpace(e.TimeType)) sb.Append("<div class=\"small\">Time basis: ").Append(H(e.TimeType)).Append("</div>");
                        sb.Append("</td><td>").Append(e.Confidence).AppendLine("%</td></tr>");
                    }
                    sb.AppendLine("</tbody></table></details>");
                    firstDate = false;
                }
            }

            sb.AppendLine("<details><summary>Undated disk/source evidence</summary>");
            sb.AppendLine("<p class=\"small\">These items are important but the source did not expose an exact event time, such as names-only file evidence or grouped source-project roots.</p>");
            sb.AppendLine("<table><thead><tr><th>Event</th><th>Source</th><th>Evidence</th><th>Confidence</th></tr></thead><tbody>");
            var undated = items.Where(e => string.IsNullOrWhiteSpace(e.When)).ToList();
            if (undated.Count == 0)
            {
                AppendEmptyRow(sb, 4, "No undated disk/source evidence was added.");
            }
            else
            {
                foreach (var e in undated)
                {
                    sb.Append("<tr class=\"search-item\"><td>");
                    AppendSeverityBadge(sb, e.Severity);
                    sb.Append("<br><span class=\"finding-title\">").Append(H(e.EventType)).Append("</span></td><td>").Append(H(e.Source)).Append("</td><td><div class=\"finding-title\">").Append(H(r.Text(e.Summary))).Append("</div><div class=\"mono small\">").Append(H(r.Text(e.Evidence))).Append("</div>");
                    if (!string.IsNullOrWhiteSpace(e.TimeType)) sb.Append("<div class=\"small\">Time basis: ").Append(H(e.TimeType)).Append("</div>");
                    sb.Append("</td><td>").Append(e.Confidence).AppendLine("%</td></tr>");
                }
            }
            sb.AppendLine("</tbody></table></details></details></section>");
        }

        private static void WriteScoreBreakdownHtml(StringBuilder sb, ScoreAssessment assessment)
        {
            sb.AppendLine("<section id=\"scoring\" class=\"wiki-section\"><details><summary>Scoring breakdown</summary>");
            sb.AppendLine("<table><thead><tr><th>Category</th><th>Weighted points</th><th>Raw points</th><th>Detected findings</th><th>Strongest evidence</th></tr></thead><tbody>");
            if (assessment.Categories.Count == 0)
            {
                AppendEmptyRow(sb, 5, "No scored categories were produced.");
            }
            else
            {
                foreach (var c in assessment.Categories)
                {
                    sb.Append("<tr class=\"search-item\"><td>").Append(H(ScannerHelpers.ReportCategoryLabel(c.Category))).Append("</td><td>").Append(Math.Round(c.AdjustedPoints, 0).ToString(CultureInfo.InvariantCulture)).Append("</td><td>").Append(Math.Round(c.RawPoints, 0).ToString(CultureInfo.InvariantCulture)).Append("</td><td>").Append(c.FindingCount).Append("<br><span class=\"small\">Max: ").Append(H(c.MaxSeverity.ToString())).Append(", ").Append(c.MaxConfidence).Append("%</span></td><td>").Append(H(c.StrongestFinding)).AppendLine("</td></tr>");
                }
            }
            sb.AppendLine("</tbody></table></details></section>");
        }

        private static void WriteFindingsHtml(StringBuilder sb, List<Finding> ordered, Redactor r)
        {
            sb.Append("<section id=\"findings\" class=\"wiki-section\"><details><summary>Detailed findings <span class=\"summary-meta\">(").Append(ordered.Count).AppendLine(" total)</span></summary>");
            sb.AppendLine("<p class=\"small\">Open a category to see what was detected, the confidence level, and the score contribution.</p>");
            if (ordered.Count == 0)
            {
                sb.AppendLine("<p class=\"small search-item\">No findings were produced.</p>");
            }
            else
            {
                foreach (var group in ordered.GroupBy(f => f.Category))
                {
                    int positiveCount = group.Count(f => f.Score > 0);
                    var strongestSeverity = group.Max(f => f.Severity);
                    sb.Append("<details><summary>").Append(H(ScannerHelpers.ReportCategoryLabel(group.Key))).Append(" <span class=\"summary-meta\">(").Append(group.Count()).Append(group.Count() == 1 ? " finding" : " findings").Append(", max ").Append(H(strongestSeverity.ToString()));
                    if (positiveCount > 0) sb.Append(", ").Append(positiveCount).Append(" scored");
                    sb.AppendLine(")</span></summary>");
                    sb.AppendLine("<table><thead><tr><th>Severity</th><th>What was detected</th><th>Confidence</th><th>Score</th></tr></thead><tbody>");
                    foreach (var f in group)
                    {
                        sb.Append("<tr class=\"search-item\"><td>");
                        AppendSeverityBadge(sb, f.Severity);
                        sb.Append("</td><td><div class=\"finding-title\">").Append(H(f.Title)).Append("</div><div class=\"finding-details\">").Append(H(r.Text(ScannerHelpers.FriendlyTimestampText(f.Details)))).Append("</div></td><td>").Append(f.Confidence).Append("%</td><td>");
                        if (f.Score > 0) sb.Append("+");
                        sb.Append(f.Score).AppendLine("</td></tr>");
                    }
                    sb.AppendLine("</tbody></table></details>");
                }
            }
            sb.AppendLine("</details></section>");
        }

        private static void WriteDriversHtml(StringBuilder sb, List<DriverInfo> items, Redactor r)
        {
            sb.AppendLine("<section id=\"drivers\" class=\"wiki-section\"><details><summary>Non-Windows loaded drivers</summary>");
            sb.AppendLine("<p class=\"small\">This lists loaded drivers outside the Windows directory with trust, service, path, and hash information.</p>");
            sb.AppendLine("<table><thead><tr><th>Name</th><th>Trust</th><th>Company</th><th>Service</th><th>Path / SHA-256</th></tr></thead><tbody>");
            var shown = items.Where(d => !d.WindowsSystemPath).OrderByDescending(d => d.SuspiciousNamePattern).ThenBy(d => d.Name).Take(1500).ToList();
            if (shown.Count == 0)
            {
                AppendEmptyRow(sb, 5, "No non-Windows loaded drivers were found.");
            }
            else
            {
                foreach (var d in shown)
                {
                    sb.Append("<tr class=\"search-item\"><td>").Append(H(d.Name));
                    if (d.SuspiciousNamePattern) sb.Append(" <span class=\"badge sev-medium\">Pattern</span>");
                    sb.Append("</td><td>").Append(d.SignedTrusted ? "Trusted" : "Untrusted/Unknown").Append("</td><td>").Append(H(string.IsNullOrWhiteSpace(d.Company) ? "Unknown" : d.Company)).Append("</td><td>");
                    if (d.Service != null) sb.Append(H(d.Service.ServiceName)).Append("<br><span class=\"small\">").Append(H(d.Service.StartType)).Append(" / ").Append(H(d.Service.CurrentState)).Append("</span>");
                    else sb.Append("<span class=\"small\">No matched service</span>");
                    sb.Append("</td><td class=\"mono\">").Append(H(r.Path(d.Path)));
                    if (!string.IsNullOrWhiteSpace(d.Sha256)) sb.Append("<br>SHA-256: ").Append(H(d.Sha256));
                    sb.AppendLine("</td></tr>");
                }
            }
            sb.AppendLine("</tbody></table></details></section>");
        }

        private static void WriteHardwareHtml(StringBuilder sb, List<HardwareRecord> items, Redactor r)
        {
            sb.AppendLine("<section id=\"hardware\" class=\"wiki-section\"><details><summary>Hardware identity records</summary>");
            sb.AppendLine("<p class=\"small\">This lists hardware identity values collected from Windows WMI and registry views.</p>");
            sb.AppendLine("<table><thead><tr><th>Category</th><th>Name</th><th>Value</th><th>Source</th></tr></thead><tbody>");
            if (items.Count == 0) AppendEmptyRow(sb, 4, "No hardware identity records were collected.");
            else foreach (var h in items) sb.Append("<tr class=\"search-item\"><td>").Append(H(h.Category)).Append("</td><td>").Append(H(h.Name)).Append("</td><td class=\"mono\">").Append(H(r.Text(h.Value))).Append("</td><td>").Append(H(h.Source)).AppendLine("</td></tr>");
            sb.AppendLine("</tbody></table></details></section>");
        }

        private static void WriteDevicesHtml(StringBuilder sb, List<DeviceConnectionRecord> items, Redactor r)
        {
            sb.AppendLine("<section id=\"usb\" class=\"wiki-section\"><details><summary>External USB connection history</summary>");
            sb.AppendLine("<p class=\"small\">This lists USB and USB storage devices retained by Windows, including available arrival/removal times.</p>");
            sb.AppendLine("<table><thead><tr><th>Device</th><th>When</th><th>Present</th><th>Type / Service</th><th>Device ID</th></tr></thead><tbody>");
            if (items.Count == 0)
            {
                AppendEmptyRow(sb, 5, "Windows did not return retained USB device-history records.");
            }
            else
            {
                foreach (var d in items)
                {
                    sb.Append("<tr class=\"search-item\"><td>").Append(H(r.Text(string.IsNullOrWhiteSpace(d.Description) ? "Unknown USB device" : d.Description)));
                    if (!string.IsNullOrWhiteSpace(d.Manufacturer)) sb.Append("<br><span class=\"small\">").Append(H(r.Text(d.Manufacturer))).Append("</span>");
                    sb.Append("</td><td class=\"mono\">Best: ").Append(H(ScannerHelpers.FriendlyTimestampText(DeviceRecordBestTime(d))));
                    if (!string.IsNullOrWhiteSpace(d.LastArrivalTime)) sb.Append("<br>Last arrival: ").Append(H(ScannerHelpers.FriendlyTimestampText(d.LastArrivalTime)));
                    if (!string.IsNullOrWhiteSpace(d.LastRemovalTime)) sb.Append("<br>Last removal: ").Append(H(ScannerHelpers.FriendlyTimestampText(d.LastRemovalTime)));
                    if (!string.IsNullOrWhiteSpace(d.FirstInstallTime)) sb.Append("<br>First install: ").Append(H(ScannerHelpers.FriendlyTimestampText(d.FirstInstallTime)));
                    if (!string.IsNullOrWhiteSpace(d.InstallTime)) sb.Append("<br>Install: ").Append(H(ScannerHelpers.FriendlyTimestampText(d.InstallTime)));
                    sb.Append("</td><td>").Append(d.CurrentlyPresent ? "Yes" : "No").Append("</td><td>").Append(d.MassStorage ? "Mass storage" : "USB device").Append("<br><span class=\"small\">").Append(H(d.ClassName)).Append(" / ").Append(H(d.Service)).Append("</span></td><td class=\"mono\">").Append(H(r.DeviceId(d.DeviceId)));
                    if (!string.IsNullOrWhiteSpace(d.Location)) sb.Append("<br><span class=\"small\">").Append(H(r.Text(d.Location))).Append("</span>");
                    sb.AppendLine("</td></tr>");
                }
            }
            sb.AppendLine("</tbody></table></details></section>");
        }

        private static void WriteSourceProjectsHtml(StringBuilder sb, List<SourceProjectSummary> items, Redactor r)
        {
            sb.AppendLine("<section id=\"software-source\" class=\"wiki-section\"><details><summary>Cheat software, source project, and build evidence</summary>");
            sb.AppendLine("<p class=\"small\">This lists cheat software, source/build projects, mappers, injectors, spoofers, and trace-cleaner evidence. Generated project structures are labeled separately.</p>");
            sb.AppendLine("<table><thead><tr><th>Severity</th><th>Project/root</th><th>Determination</th><th>Counts</th><th>Examples</th></tr></thead><tbody>");
            if (items.Count == 0)
            {
                AppendEmptyRow(sb, 5, "No grouped cheat software/source/build projects were found.");
            }
            else
            {
                foreach (var g in items)
                {
                    sb.Append("<tr class=\"search-item\"><td>");
                    AppendSeverityBadge(sb, g.MaxSeverity);
                    sb.Append("</td><td class=\"mono\">").Append(H(r.Path(g.Root))).Append("</td><td><div class=\"finding-title\">").Append(H(g.Determination)).Append("</div>");
                    if (g.GeneratedStructure) sb.Append("<div class=\"small\">Type: generated/project-structure evidence, not treated the same as a compiled source repo.</div>");
                    sb.Append("<div class=\"small\">Keywords: ").Append(H(JoinLimitedSet(g.Tokens, 8))).Append("</div></td><td>Total: ").Append(g.TotalDetections).Append("<br><span class=\"small\">Source: ").Append(g.DirectSourceCount).Append("; project: ").Append(g.ProjectFileCount).Append("; build: ").Append(g.BuildArtifactCount).Append("; mapper: ").Append(g.MapperCount).Append("; injector/spoofer/cleaner: ").Append(g.InjectorSpooferTraceCount).Append("</span></td><td><details><summary>Locations</summary>");
                    foreach (var sample in g.Samples) sb.Append("<div class=\"mono small\">").Append(H(r.Path(sample))).Append("</div>");
                    sb.AppendLine("</details></td></tr>");
                }
            }
            sb.AppendLine("</tbody></table></details></section>");
        }

        private static void WriteExecutionHtml(StringBuilder sb, List<ExecutionArtifact> items, Redactor r)
        {
            sb.AppendLine("<section id=\"execution\" class=\"wiki-section\"><details><summary>Execution evidence: AmCache and Prefetch</summary>");
            sb.AppendLine("<p class=\"small\">This lists AmCache executable/install traces and Prefetch run-trace files that matched cheat, mapper, injector, trainer, debugger, or decompilation tooling names.</p>");
            sb.AppendLine("<table><thead><tr><th>Severity</th><th>Source</th><th>Detected trace</th><th>When</th><th>Confidence</th></tr></thead><tbody>");
            if (items.Count == 0)
            {
                AppendEmptyRow(sb, 5, "No AmCache or Prefetch cheat/tool execution traces were found.");
            }
            else
            {
                foreach (var e in items)
                {
                    sb.Append("<tr class=\"search-item\"><td>");
                    AppendSeverityBadge(sb, e.Severity);
                    sb.Append("</td><td>").Append(H(e.Source)).Append("</td><td><div class=\"finding-title\">").Append(H(e.Label)).Append("</div><div class=\"small\">Token: ").Append(H(e.Token)).Append("</div><div class=\"mono small\">").Append(H(e.Name)).Append("<br>").Append(H(r.Path(e.Path))).Append("</div><details><summary>Trace detail</summary><div class=\"finding-details\">").Append(H(r.Text(e.Details))).Append("</div></details></td><td class=\"mono\">").Append(H(ScannerHelpers.FriendlyTimestampText(e.When))).Append("</td><td>").Append(e.Confidence).AppendLine("%</td></tr>");
                }
            }
            sb.AppendLine("</tbody></table></details></section>");
        }

        private static void WriteBrowserDownloadsHtml(StringBuilder sb, List<BrowserDownloadMatch> items, Redactor r)
        {
            sb.AppendLine("<section id=\"browser-source-download\" class=\"wiki-section\"><details><summary>Browser source/download evidence</summary>");
            sb.AppendLine("<p class=\"small\">This separates true browser download/local-path evidence from browser source URL and history leads. A row is only treated as a download/local-path record when a valid Windows local path was extracted. The summary groups repeated browser records by domain and evidence type.</p>");

            var groups = BuildBrowserEvidenceGroups(items);
            sb.AppendLine("<h3>Grouped browser evidence summary</h3>");
            sb.AppendLine("<table><thead><tr><th>Domain</th><th>Evidence type</th><th>Counts</th><th>First / last seen</th><th>Examples</th></tr></thead><tbody>");
            if (groups.Count == 0)
            {
                AppendEmptyRow(sb, 5, "No grouped browser source/download evidence was produced.");
            }
            else
            {
                foreach (var g in groups)
                {
                    sb.Append("<tr class=\"search-item\"><td>");
                    AppendSeverityBadge(sb, g.MaxSeverity);
                    sb.Append("<br><span class=\"finding-title\">").Append(H(g.Domain)).Append("</span><br><span class=\"small\">Keywords: ").Append(H(JoinLimitedSet(g.Tokens, 8))).Append("</span></td><td>").Append(H(g.EvidenceKind)).Append("</td><td>Total: ").Append(g.TotalRecords).Append("<br><span class=\"small\">Downloads: ").Append(g.DownloadLocalCount).Append("; download URLs: ").Append(g.DownloadSourceCount).Append("; source/history: ").Append(g.SourceHistoryCount).Append("; timed: ").Append(g.TimedCount).Append("</span></td><td class=\"mono small\">");
                    if (!string.IsNullOrWhiteSpace(g.FirstSeen)) sb.Append("First: ").Append(H(ScannerHelpers.FriendlyTimestampText(g.FirstSeen))).Append("<br>Last: ").Append(H(ScannerHelpers.FriendlyTimestampText(g.LastSeen)));
                    else sb.Append("No artifact timestamp parsed");
                    sb.Append("</td><td><details><summary>Examples</summary>");
                    foreach (var sample in g.SampleEvidence) sb.Append("<div class=\"mono small\">").Append(H(r.Text(sample))).Append("</div>");
                    sb.AppendLine("</details></td></tr>");
                }
            }
            sb.AppendLine("</tbody></table>");

            var ordered = SortBrowserEvidenceForCheck(items);
            sb.AppendLine("<h3>Download/local-path evidence</h3>");
            sb.AppendLine("<table><thead><tr><th>Severity</th><th>Browser</th><th>Keyword</th><th>Download evidence</th><th>Confidence</th></tr></thead><tbody>");
            var downloadRows = ordered.Where(m => !string.IsNullOrWhiteSpace(m.LocalPath)).Take(50).ToList();
            if (downloadRows.Count == 0)
            {
                AppendEmptyRow(sb, 5, "No true browser download/local-path records were extracted. Source/history leads are listed below.");
            }
            else
            {
                foreach (var m in downloadRows) AppendBrowserEvidenceRow(sb, m, r, true);
            }
            sb.AppendLine("</tbody></table>");

            sb.AppendLine("<h3>Browser source URL / history leads</h3>");
            sb.AppendLine("<table><thead><tr><th>Severity</th><th>Browser</th><th>Keyword</th><th>Source/history evidence</th><th>Confidence</th></tr></thead><tbody>");
            var sourceRows = ordered.Where(m => string.IsNullOrWhiteSpace(m.LocalPath)).Take(50).ToList();
            if (sourceRows.Count == 0)
            {
                AppendEmptyRow(sb, 5, "No browser source/history leads matched cheat/tooling terms.");
            }
            else
            {
                foreach (var m in sourceRows) AppendBrowserEvidenceRow(sb, m, r, false);
            }
            sb.AppendLine("</tbody></table></details></section>");
        }

        private static void AppendBrowserEvidenceRow(StringBuilder sb, BrowserDownloadMatch m, Redactor r, bool download)
        {
            string clean = Shorten(ScannerHelpers.CollapseWhitespaceForDisplay(r.Text(m.Snippet)), download ? 220 : 240);
            sb.Append("<tr class=\"search-item\"><td>");
            AppendSeverityBadge(sb, m.Severity);
            sb.Append("</td><td>").Append(H(m.Browser)).Append("<br><span class=\"small\">").Append(H(m.Profile)).Append("</span></td><td>").Append(H(m.Token)).Append("<br><span class=\"small\">").Append(H(m.Label)).Append("</span></td><td><div class=\"finding-title\">").Append(H(BrowserEvidenceLabel(m))).Append("</div>");
            if (!string.IsNullOrWhiteSpace(m.When)) sb.Append("<div class=\"small\">Artifact time: ").Append(H(ScannerHelpers.FriendlyTimestampText(m.When))).Append("</div>");
            else if (!string.IsNullOrWhiteSpace(m.TimeType)) sb.Append("<div class=\"small\">Time basis: ").Append(H(m.TimeType)).Append("</div>");
            if (!string.IsNullOrWhiteSpace(m.Domain)) sb.Append("<div>Domain: ").Append(H(m.Domain)).Append("</div>");
            if (!string.IsNullOrWhiteSpace(m.Url)) sb.Append("<div class=\"mono small\">").Append(download ? "Source URL: " : "URL: ").Append(H(r.Text(m.Url))).Append("</div>");
            if (download && !string.IsNullOrWhiteSpace(m.LocalPath)) sb.Append("<div class=\"mono small\">Local path: ").Append(H(r.Path(m.LocalPath))).Append("</div>");
            if (download)
                sb.Append("<details><summary>Matched browser text</summary><div class=\"finding-details\">").Append(H(clean)).Append("</div><div class=\"mono small\">").Append(H(r.Path(m.HistoryPath))).Append("</div></details>");
            else
                sb.Append("<div class=\"finding-details\">").Append(H(clean)).Append("</div><details><summary>History database</summary><div class=\"mono small\">").Append(H(r.Path(m.HistoryPath))).Append("</div></details>");
            sb.Append("</td><td>").Append(m.Confidence).AppendLine("%</td></tr>");
        }

        private static void WriteRuntimeHtml(StringBuilder sb, List<RuntimeArtifact> items, Redactor r)
        {
            sb.AppendLine("<section id=\"runtime\" class=\"wiki-section\"><details><summary>Running processes, services, drivers, and startup detections</summary>");
            sb.AppendLine("<p class=\"small\">This lists running processes, Windows service/driver registry entries, scheduled tasks, and Run/RunOnce startup entries that matched cheat/tooling names.</p>");
            sb.AppendLine("<table><thead><tr><th>Severity</th><th>Source</th><th>Detected artifact</th><th>Path/detail</th><th>Confidence</th></tr></thead><tbody>");
            if (items.Count == 0)
            {
                AppendEmptyRow(sb, 5, "No running, service, driver, scheduled-task, or startup cheat/tooling artifacts were found.");
            }
            else
            {
                foreach (var m in items)
                {
                    sb.Append("<tr class=\"search-item\"><td>");
                    AppendSeverityBadge(sb, m.Severity);
                    sb.Append("</td><td>").Append(H(m.SourceType)).Append("</td><td><div class=\"finding-title\">").Append(H(m.Label)).Append("</div><div class=\"small\">Token: ").Append(H(m.Token)).Append("</div><div>").Append(H(m.Name)).Append("</div></td><td><div class=\"mono small\">").Append(H(r.Path(m.Path))).Append("</div><div class=\"finding-details\">").Append(H(r.Text(m.Details))).Append("</div></td><td>").Append(m.Confidence).AppendLine("%</td></tr>");
                }
            }
            sb.AppendLine("</tbody></table></details></section>");
        }

        private static void WriteInstalledProgramsHtml(StringBuilder sb, List<FileNameMatch> items, Redactor r)
        {
            sb.AppendLine("<section id=\"installed-programs\" class=\"wiki-section\"><details><summary>Installed program/tool detections</summary>");
            sb.AppendLine("<p class=\"small\">This lists installed-program registry entries that matched configured cheat, trainer, disassembler, decompiler, debugger, or process-inspection tool names.</p>");
            sb.AppendLine("<table><thead><tr><th>Severity</th><th>Program/tool</th><th>Matched keyword</th><th>Confidence</th></tr></thead><tbody>");
            if (items.Count == 0)
            {
                AppendEmptyRow(sb, 4, "No installed program/tool detections were found.");
            }
            else
            {
                foreach (var m in items)
                {
                    sb.Append("<tr class=\"search-item\"><td>");
                    AppendSeverityBadge(sb, m.Severity);
                    sb.Append("</td><td><div class=\"finding-title\">").Append(H(m.Label)).Append("</div><div class=\"mono small\">").Append(H(r.Path(m.Path))).Append("</div></td><td>").Append(H(m.Token)).Append("</td><td>").Append(m.Confidence).AppendLine("%</td></tr>");
                }
            }
            sb.AppendLine("</tbody></table></details></section>");
        }

        private static void WriteBrowserHtml(StringBuilder sb, List<BrowserHistoryMatch> matches, List<BrowserHistorySource> sources, Redactor r)
        {
            sb.AppendLine("<section id=\"browser-keywords\" class=\"wiki-section\"><details><summary>Browser/domain keyword detections</summary>");
            sb.AppendLine("<p class=\"small\">This lists supported browser history stores and the cleaned keyword-hit records that matched cheat/tooling terms.</p>");
            sb.AppendLine("<table><thead><tr><th>Browser</th><th>Profile</th><th>Local history database</th></tr></thead><tbody>");
            if (sources.Count == 0) AppendEmptyRow(sb, 3, "No supported browser history stores were detected.");
            else foreach (var src in sources) sb.Append("<tr class=\"search-item\"><td>").Append(H(src.Browser)).Append("</td><td>").Append(H(src.Profile)).Append("</td><td class=\"mono\">").Append(H(r.Path(src.HistoryPath))).AppendLine("</td></tr>");
            sb.AppendLine("</tbody></table>");
            sb.AppendLine("<table><thead><tr><th>Severity</th><th>Browser profile</th><th>Keyword</th><th>Matched page/search</th><th>Confidence</th></tr></thead><tbody>");
            if (matches.Count == 0)
            {
                AppendEmptyRow(sb, 5, "No browser keyword detections were found.");
            }
            else
            {
                foreach (var m in matches)
                {
                    string cleanSnippet = ScannerHelpers.CollapseWhitespaceForDisplay(r.Text(m.Snippet));
                    string url = ExtractFirstUrl(cleanSnippet);
                    string domain = DomainFromUrlLoose(url);
                    sb.Append("<tr class=\"search-item\"><td>");
                    AppendSeverityBadge(sb, m.Severity);
                    sb.Append("</td><td>").Append(H(m.Browser)).Append("<br><span class=\"small\">").Append(H(m.Profile)).Append("</span></td><td>").Append(H(m.Token)).Append("<br><span class=\"small\">").Append(H(m.Label)).Append("</span></td><td>");
                    if (!string.IsNullOrWhiteSpace(domain)) sb.Append("<div class=\"finding-title\">").Append(H(domain)).Append("</div>");
                    if (!string.IsNullOrWhiteSpace(url)) sb.Append("<div class=\"mono small\">").Append(H(url)).Append("</div>");
                    sb.Append("<div class=\"finding-details\">").Append(H(cleanSnippet)).Append("</div><details><summary>History database</summary><div class=\"mono small\">").Append(H(r.Path(m.HistoryPath))).Append("</div></details></td><td>").Append(m.Confidence).AppendLine("%</td></tr>");
                }
            }
            sb.AppendLine("</tbody></table></details></section>");
        }

        private static void WriteFileMatchesHtml(StringBuilder sb, List<FileNameMatch> items, Redactor r)
        {
            sb.AppendLine("<section id=\"file-names\" class=\"wiki-section\"><details><summary>File/folder name detections</summary>");
            sb.AppendLine("<p class=\"small\">This lists grouped file and folder name detections. File contents were not read.</p>");
            var groups = BuildFileEvidenceGroups(items, r);
            sb.AppendLine("<table><thead><tr><th>Severity</th><th>Evidence root</th><th>Detections</th><th>Keywords</th><th>Summary / examples</th></tr></thead><tbody>");
            if (groups.Count == 0)
            {
                AppendEmptyRow(sb, 5, "No file/folder name detections were found.");
            }
            else
            {
                foreach (var g in groups)
                {
                    sb.Append("<tr class=\"search-item\"><td>");
                    AppendSeverityBadge(sb, g.MaxSeverity);
                    sb.Append("</td><td class=\"mono\">").Append(H(g.Root)).Append("</td><td>").Append(g.Count).Append("<br><span class=\"small\">Direct/source: ").Append(g.DirectSourceCount).Append("; mapper: ").Append(g.KernelMapperCount).Append("; injector/spoofer/cleaner: ").Append(g.InjectorSpooferTraceCount).Append("</span></td><td>").Append(H(JoinLimitedSet(g.Tokens, 6))).Append("</td><td><div class=\"finding-title\">").Append(H(JoinLimitedSet(g.Labels, 3))).Append("</div><div class=\"small\">Highest confidence: ").Append(g.MaxConfidence).Append("%</div><details><summary>Locations</summary>");
                    foreach (var sample in g.Samples) sb.Append("<div class=\"mono small\">").Append(H(sample)).Append("</div>");
                    sb.AppendLine("</details></td></tr>");
                }
            }
            sb.AppendLine("</tbody></table></details></section>");
        }

        private sealed class FileEvidenceGroup
        {
            public string Root = "";
            public int Count;
            public Severity MaxSeverity = Severity.Info;
            public int MaxConfidence;
            public int MaxScore;
            public int DirectSourceCount;
            public int KernelMapperCount;
            public int InjectorSpooferTraceCount;
            public SortedSet<string> Tokens = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            public SortedSet<string> Labels = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            public List<string> Samples = new List<string>();
        }

        private sealed class BrowserEvidenceGroup
        {
            public string GroupKey = "";
            public string Domain = "";
            public string EvidenceKind = "";
            public int TotalRecords;
            public int DownloadLocalCount;
            public int DownloadSourceCount;
            public int SourceHistoryCount;
            public int SnippetOnlyCount;
            public int HighConfidenceCount;
            public int MediumConfidenceCount;
            public int TimedCount;
            public string FirstSeen = "";
            public string LastSeen = "";
            public Severity MaxSeverity = Severity.Info;
            public int MaxConfidence;
            public int MaxScore;
            public SortedSet<string> Tokens = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            public SortedSet<string> Labels = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            public List<string> SampleEvidence = new List<string>();
        }

        private static List<string> BuildCaseSummaryItems(List<FileNameMatch> fileMatches, List<BrowserHistoryMatch> browserMatches, List<ExecutionArtifact> executionArtifacts, List<BrowserDownloadMatch> browserDownloadMatches, List<RuntimeArtifact> runtimeArtifacts, List<SourceProjectSummary> sourceProjects)
        {
            int directSource = fileMatches.Count(IsDirectCheatSourceMatch);
            int mapper = fileMatches.Count(m => ContainsInsensitive(m.Token, "kdmapper") || ContainsInsensitive(m.Label, "mapper"));
            int injectorFiles = fileMatches.Count(m => ContainsInsensitive(m.Token, "injector") || ContainsInsensitive(m.Label, "injector") || ContainsInsensitive(m.Token, "spoofer") || ContainsInsensitive(m.Label, "spoofer") || ContainsInsensitive(m.Token, "trace cleaner") || ContainsInsensitive(m.Label, "trace-cleaner"));
            int trueDownloads = browserDownloadMatches.Count(d => !string.IsNullOrWhiteSpace(d.LocalPath));
            int browserSourceLeads = browserDownloadMatches.Count(d => string.IsNullOrWhiteSpace(d.LocalPath));
            int highExec = executionArtifacts.Count(e => e.Severity == Severity.High || e.Severity == Severity.Critical);
            int injectorExec = executionArtifacts.Count(e => ContainsInsensitive(e.Token, "injector") || ContainsInsensitive(e.Label, "injector"));
            int strongBrowser = browserMatches.Count(IsStrongBrowserHistoryMatch);
            int runtime = runtimeArtifacts.Count;

            var items = new List<string>();
            if (trueDownloads > 0 && sourceProjects.Count > 0 && (highExec > 0 || injectorExec > 0)) items.Add("Corroboration chain present: browser download/local-path records, grouped source/build evidence, and execution traces were all found.");
            else if (trueDownloads > 0 && sourceProjects.Count > 0) items.Add("Corroboration chain present: browser download/local-path records and grouped source/build evidence were both found.");
            else if (sourceProjects.Count > 0 && (highExec > 0 || injectorExec > 0)) items.Add("Corroboration chain present: grouped source/build evidence and execution traces were both found.");
            if (sourceProjects.Count > 0) items.Add(sourceProjects.Count + " source/build project grouping(s) were found.");
            if (directSource > 0) items.Add(directSource + " direct cheat/source-code file or folder-name artifact(s) were found.");
            if (trueDownloads > 0) items.Add(trueDownloads + " browser download/local-path record(s) point to cheat, injector, source, or tooling files.");
            if (highExec > 0) items.Add(highExec + " high-confidence execution trace(s) were found in AmCache or Prefetch.");
            if (injectorExec > 0) items.Add(injectorExec + " injector execution trace(s) were found.");
            if (mapper > 0) items.Add(mapper + " kernel mapper/bypass artifact(s) were found on disk.");
            if (injectorFiles > 0) items.Add(injectorFiles + " injector/spoofer/trace-cleaner style file artifact(s) were found on disk.");
            if (strongBrowser > 0) items.Add(strongBrowser + " strong cheat-domain/search browser-history indicator(s) were found.");
            if (browserSourceLeads > 0) items.Add(browserSourceLeads + " browser source/history lead(s) were found beyond local-download records.");
            if (runtime > 0) items.Add(runtime + " running/startup/service artifact(s) matched configured cheat/tooling indicators.");
            if (items.Count == 0) items.Add("No direct cheat/tooling evidence was found in the enabled high-signal categories.");
            return items;
        }

        private static string BuildSummaryText(ScanReport report, List<FileNameMatch> installedProgramMatches, List<FileNameMatch> fileMatches, List<BrowserHistoryMatch> browserMatches, List<ExecutionArtifact> executionArtifacts, List<BrowserDownloadMatch> browserDownloadMatches, List<RuntimeArtifact> runtimeArtifacts, List<SourceProjectSummary> sourceProjects)
        {
            int directSource = fileMatches.Count(IsDirectCheatSourceMatch);
            int mapper = fileMatches.Count(m => ContainsInsensitive(m.Token, "kdmapper") || ContainsInsensitive(m.Label, "mapper"));
            int injector = fileMatches.Count(m => ContainsInsensitive(m.Token, "injector") || ContainsInsensitive(m.Label, "injector"));
            int cleanup = fileMatches.Count(m => ContainsInsensitive(m.Token, "trace cleaner") || ContainsInsensitive(m.Label, "trace-cleaner"));
            int highExec = executionArtifacts.Count(e => e.Severity == Severity.High || e.Severity == Severity.Critical);
            int injectorExec = executionArtifacts.Count(e => ContainsInsensitive(e.Token, "injector") || ContainsInsensitive(e.Label, "injector"));
            int downloadPaths = browserDownloadMatches.Count(d => !string.IsNullOrWhiteSpace(d.LocalPath));
            int sourceLeads = browserDownloadMatches.Count(d => string.IsNullOrWhiteSpace(d.LocalPath));
            int strongBrowser = browserMatches.Count(IsStrongBrowserHistoryMatch);

            var parts = new List<string>();
            if (sourceProjects.Count > 0) parts.Add(sourceProjects.Count + " grouped cheat software/source-project roots");
            if (directSource > 0) parts.Add(directSource + " direct cheat source/code name detections");
            if (mapper > 0) parts.Add(mapper + " kernel-mapper artifacts");
            if (injector > 0) parts.Add(injector + " injector artifacts");
            if (cleanup > 0) parts.Add(cleanup + " trace-cleaner artifacts");
            if (highExec > 0) parts.Add(highExec + " high-confidence execution traces");
            if (injectorExec > 0) parts.Add(injectorExec + " injector execution traces");
            if (downloadPaths > 0) parts.Add(downloadPaths + " browser download/local-path records");
            if (sourceLeads > 0) parts.Add(sourceLeads + " browser source/history leads");
            if (strongBrowser > 0) parts.Add(strongBrowser + " strong cheat-domain/search history detections");
            if (installedProgramMatches.Count > 0) parts.Add(installedProgramMatches.Count + " installed cheat/decompilation tools");
            if (runtimeArtifacts.Count > 0) parts.Add(runtimeArtifacts.Count + " running/startup/service artifacts");
            string core = parts.Count == 0 ? "no direct cheat/tooling evidence in the enabled evidence categories" : string.Join(", ", parts);
            return "This PC shows " + core + ". Check downloads, launch traces, grouped projects, browser source/download hits, and installed/running tools before lower-signal posture findings.";
        }

        private static List<FileEvidenceGroup> BuildFileEvidenceGroups(List<FileNameMatch> matches, Redactor r)
        {
            var groups = new Dictionary<string, FileEvidenceGroup>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in matches)
            {
                string displayPath = r.Path(m.Path);
                string root = EvidenceRootForPath(displayPath);
                FileEvidenceGroup g;
                if (!groups.TryGetValue(root, out g))
                {
                    g = new FileEvidenceGroup { Root = root };
                    groups[root] = g;
                }
                g.Count++;
                if (!string.IsNullOrWhiteSpace(m.Token)) g.Tokens.Add(m.Token);
                if (!string.IsNullOrWhiteSpace(m.Label)) g.Labels.Add(m.Label);
                if (m.Severity > g.MaxSeverity) g.MaxSeverity = m.Severity;
                g.MaxConfidence = Math.Max(g.MaxConfidence, m.Confidence);
                g.MaxScore = Math.Max(g.MaxScore, m.Score);
                if (IsDirectCheatSourceMatch(m)) g.DirectSourceCount++;
                if (ContainsInsensitive(m.Token, "kdmapper") || ContainsInsensitive(m.Token, "driver mapper") || ContainsInsensitive(m.Label, "Kernel driver mapper") || ContainsInsensitive(m.Label, "mapper")) g.KernelMapperCount++;
                if (ContainsInsensitive(m.Token, "injector") || ContainsInsensitive(m.Token, "spoofer") || ContainsInsensitive(m.Token, "trace cleaner") || ContainsInsensitive(m.Label, "injector") || ContainsInsensitive(m.Label, "spoofer") || ContainsInsensitive(m.Label, "trace-cleaner")) g.InjectorSpooferTraceCount++;
                if (g.Samples.Count < 8) g.Samples.Add(displayPath);
            }
            return groups.Values.OrderByDescending(g => g.MaxScore).ThenByDescending(g => g.MaxSeverity).ThenByDescending(g => g.DirectSourceCount).ThenByDescending(g => g.Count).ToList();
        }

        private static string EvidenceRootForPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return path ?? "";
            var parts = path.Replace('/', '\\').Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries).ToList();
            if (parts.Count == 0) return path;
            for (int i = 0; i < parts.Count; i++)
            {
                string lower = parts[i].ToLowerInvariant();
                if ((lower == "desktop" || lower == "downloads" || lower == "documents" || lower == "repos" || lower == "projects" || lower == "github") && i + 1 < parts.Count)
                    return string.Join("\\", parts.Take(Math.Min(parts.Count, i + 2)));
            }
            return string.Join("\\", parts.Take(Math.Min(parts.Count, 4)));
        }

        private static List<BrowserEvidenceGroup> BuildBrowserEvidenceGroups(List<BrowserDownloadMatch> matches)
        {
            var groups = new Dictionary<string, BrowserEvidenceGroup>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in matches)
            {
                string domain = string.IsNullOrWhiteSpace(m.Domain) ? DomainFromUrlLoose(m.Url) : m.Domain;
                if (string.IsNullOrWhiteSpace(domain)) domain = "No extracted domain";
                string kind;
                if (!string.IsNullOrWhiteSpace(m.LocalPath)) kind = "Download/local path";
                else if (ContainsInsensitive(m.EvidenceType, "download")) kind = "Download source URL";
                else if (!string.IsNullOrWhiteSpace(m.Url)) kind = "Source/history URL";
                else kind = "Snippet-only lead";
                string key = domain.ToLowerInvariant() + "|" + kind.ToLowerInvariant();
                BrowserEvidenceGroup g;
                if (!groups.TryGetValue(key, out g))
                {
                    g = new BrowserEvidenceGroup { GroupKey = key, Domain = domain, EvidenceKind = kind };
                    groups[key] = g;
                }
                g.TotalRecords++;
                if (!string.IsNullOrWhiteSpace(m.LocalPath)) g.DownloadLocalCount++;
                else if (ContainsInsensitive(m.EvidenceType, "download")) g.DownloadSourceCount++;
                else if (!string.IsNullOrWhiteSpace(m.Url)) g.SourceHistoryCount++;
                else g.SnippetOnlyCount++;
                if (m.Severity == Severity.High || m.Severity == Severity.Critical) g.HighConfidenceCount++;
                if (m.Severity == Severity.Medium) g.MediumConfidenceCount++;
                if (m.Severity > g.MaxSeverity) g.MaxSeverity = m.Severity;
                g.MaxConfidence = Math.Max(g.MaxConfidence, m.Confidence);
                g.MaxScore = Math.Max(g.MaxScore, m.Score);
                if (!string.IsNullOrWhiteSpace(m.Token)) g.Tokens.Add(m.Token);
                if (!string.IsNullOrWhiteSpace(m.Label)) g.Labels.Add(m.Label);
                UpdateFirstLastBrowserTime(g, m.When);
                if (g.SampleEvidence.Count < 5)
                {
                    string sample = BrowserDownloadEvidenceText(m);
                    if (!string.IsNullOrWhiteSpace(sample)) g.SampleEvidence.Add(sample);
                }
            }
            return groups.Values.OrderByDescending(g => g.DownloadLocalCount).ThenByDescending(g => g.HighConfidenceCount).ThenByDescending(g => g.TotalRecords).ThenByDescending(g => g.MaxConfidence).ThenBy(g => g.Domain).ToList();
        }

        private static void UpdateFirstLastBrowserTime(BrowserEvidenceGroup g, string when)
        {
            if (string.IsNullOrWhiteSpace(when)) return;
            g.TimedCount++;
            if (string.IsNullOrWhiteSpace(g.FirstSeen) || string.CompareOrdinal(when, g.FirstSeen) < 0) g.FirstSeen = when;
            if (string.IsNullOrWhiteSpace(g.LastSeen) || string.CompareOrdinal(when, g.LastSeen) > 0) g.LastSeen = when;
        }

        private static List<BrowserDownloadMatch> SortBrowserEvidenceForCheck(List<BrowserDownloadMatch> matches)
        {
            return matches.OrderBy(m => BrowserEvidenceTypeRank(m)).ThenByDescending(m => m.Score).ThenByDescending(m => m.Confidence).ThenByDescending(m => m.When ?? "").ThenBy(m => BrowserDownloadEvidenceText(m)).ToList();
        }

        private static int BrowserEvidenceTypeRank(BrowserDownloadMatch m)
        {
            if (!string.IsNullOrWhiteSpace(m.LocalPath)) return 0;
            if (ContainsInsensitive(m.EvidenceType, "download")) return 1;
            if (!string.IsNullOrWhiteSpace(m.Url)) return 2;
            return 3;
        }

        private static string BrowserEvidenceLabel(BrowserDownloadMatch m)
        {
            if (!string.IsNullOrWhiteSpace(m.EvidenceType)) return m.EvidenceType;
            if (!string.IsNullOrWhiteSpace(m.LocalPath)) return "Download/local path";
            if (!string.IsNullOrWhiteSpace(m.Url)) return "Source/history URL";
            return "Snippet-only lead";
        }

        private static string BrowserDownloadEvidenceText(BrowserDownloadMatch m)
        {
            if (!string.IsNullOrWhiteSpace(m.LocalPath)) return m.LocalPath;
            if (!string.IsNullOrWhiteSpace(m.Url)) return m.Url;
            return Shorten(ScannerHelpers.CollapseWhitespaceForDisplay(m.Snippet), 220);
        }

        private static string ExtractFirstUrl(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return "";
            var match = System.Text.RegularExpressions.Regex.Match(text, @"https?://[^\s""'<>|\\]+", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (!match.Success) return "";
            string url = match.Value.TrimEnd('.', ',', ';', ')', ']');
            return Shorten(url, 180);
        }

        private static string DomainFromUrlLoose(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return "";
            Uri uri;
            if (Uri.TryCreate(url, UriKind.Absolute, out uri) && !string.IsNullOrWhiteSpace(uri.Host))
                return uri.Host.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? uri.Host.Substring(4).ToLowerInvariant() : uri.Host.ToLowerInvariant();
            string value = url;
            int protocol = value.IndexOf("://", StringComparison.Ordinal);
            int start = protocol >= 0 ? protocol + 3 : 0;
            int end = value.IndexOfAny(new[] { '/', '?', '#' }, start);
            string domain = end >= 0 ? value.Substring(start, end - start) : value.Substring(start);
            domain = domain.ToLowerInvariant();
            return domain.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? domain.Substring(4) : domain;
        }

        private static string DeviceRecordBestTime(DeviceConnectionRecord r)
        {
            if (!string.IsNullOrWhiteSpace(r.LastArrivalTime)) return r.LastArrivalTime;
            if (!string.IsNullOrWhiteSpace(r.InstallTime)) return r.InstallTime;
            if (!string.IsNullOrWhiteSpace(r.FirstInstallTime)) return r.FirstInstallTime;
            if (!string.IsNullOrWhiteSpace(r.LastRemovalTime)) return r.LastRemovalTime;
            return "not reported";
        }

        private static string JoinLimitedSet(IEnumerable<string> values, int limit)
        {
            var filtered = (values ?? new string[0]).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).Take(limit + 1).ToList();
            if (filtered.Count == 0) return "-";
            int extra = Math.Max(0, (values ?? new string[0]).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).Count() - limit);
            var shown = filtered.Take(limit).ToList();
            string result = string.Join(", ", shown);
            if (extra > 0) result += ", +" + extra + " more";
            return result;
        }

        private static string Shorten(string value, int max)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= max) return value ?? "";
            return value.Substring(0, Math.Max(0, max - 3)) + "...";
        }

        private static bool IsDirectCheatSourceMatch(FileNameMatch m)
        {
            string text = ((m.Token ?? "") + " " + (m.Label ?? "") + " " + (m.Path ?? "") + " " + (m.Category ?? "")).ToLowerInvariant();
            return text.Contains("source") || text.Contains("src") || text.Contains("project") || text.Contains(".sln") || text.Contains(".vcxproj") || text.Contains(".csproj") || text.Contains("cheat") || text.Contains("aimbot") || text.Contains("esp") || text.Contains("ragebot");
        }

        private static bool IsStrongBrowserHistoryMatch(BrowserHistoryMatch b)
        {
            if (b.Severity == Severity.High || b.Severity == Severity.Critical) return true;
            string text = ((b.Token ?? "") + " " + (b.Label ?? "") + " " + (b.Snippet ?? "")).ToLowerInvariant();
            return text.Contains("unknowncheats") || text.Contains("elitepvpers") || text.Contains("aimbot") || text.Contains("triggerbot") || text.Contains("wallhack") || text.Contains("ragebot") || text.Contains("kdmapper") || text.Contains("injector") || text.Contains("spoofer") || text.Contains("bypass");
        }

        private static bool ContainsInsensitive(string value, string token)
        {
            return !string.IsNullOrEmpty(value) && !string.IsNullOrEmpty(token) && value.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static void Prop(StringBuilder sb, int indent, string name, string value, bool comma)
        {
            sb.Append(Indent(indent)).Append("\"").Append(J(name)).Append("\": \"").Append(J(value)).Append("\"").AppendLine(comma ? "," : "");
        }

        private static void Prop(StringBuilder sb, int indent, string name, int value, bool comma)
        {
            sb.Append(Indent(indent)).Append("\"").Append(J(name)).Append("\": ").Append(value).AppendLine(comma ? "," : "");
        }

        private static void Prop(StringBuilder sb, int indent, string name, bool value, bool comma)
        {
            sb.Append(Indent(indent)).Append("\"").Append(J(name)).Append("\": ").Append(value ? "true" : "false").AppendLine(comma ? "," : "");
        }

        private static void PropArray(StringBuilder sb, int indent, string name, IEnumerable<string> values, bool comma)
        {
            sb.Append(Indent(indent)).Append("\"").Append(J(name)).Append("\": [");
            bool first = true;
            foreach (var v in values ?? new string[0])
            {
                if (!first) sb.Append(", ");
                sb.Append("\"").Append(J(v)).Append("\"");
                first = false;
            }
            sb.Append("]").AppendLine(comma ? "," : "");
        }

        private static string J(string value) => ScannerHelpers.JsonEscape(value ?? "");
        private static string H(string value) => ScannerHelpers.HtmlEscape(value ?? "");
        private static string Indent(int count) => new string(' ', count * 2);

        private static string Css()
        {
            return @":root {
  --bg:#f6f8fb; --page:#ffffff; --ink:#1f2933; --muted:#607083; --line:#d9e2ec;
  --soft:#eef3f8; --soft2:#f8fafc; --link:#1d4ed8; --info:#2563eb; --low:#15803d;
  --medium:#b45309; --high:#b91c1c; --critical:#7f1d1d; --shadow:0 1px 3px rgba(15,23,42,.08);
}
* { box-sizing:border-box; }
html { scroll-behavior:smooth; }
body { margin:0; background:var(--bg); color:var(--ink); font-family:Segoe UI, Arial, sans-serif; line-height:1.5; }
a { color:var(--link); text-decoration:none; }
a:hover { text-decoration:underline; }
.wrapper { max-width:none; margin:0; padding:0; }
.wiki-topbar { position:sticky; top:0; z-index:20; background:rgba(255,255,255,.96); backdrop-filter:blur(10px); border-bottom:1px solid var(--line); }
.wiki-topbar-inner { max-width:1440px; margin:0 auto; padding:14px 22px; display:flex; gap:18px; align-items:center; justify-content:space-between; }
.wiki-brand { min-width:240px; }
.wiki-title { font-size:20px; font-weight:800; margin:0; }
.wiki-subtitle { color:var(--muted); font-size:12px; margin-top:2px; }
.wiki-search { flex:1; max-width:720px; }
.wiki-search input { width:100%; border:1px solid var(--line); border-radius:8px; padding:11px 12px; font-size:14px; background:var(--soft2); color:var(--ink); }
.wiki-search input:focus { outline:2px solid rgba(37,99,235,.18); border-color:#93b4e8; background:white; }
.search-help { color:var(--muted); font-size:12px; margin-top:5px; }
.wiki-layout { max-width:1440px; margin:0 auto; display:grid; grid-template-columns:260px minmax(0,1fr); gap:22px; padding:22px; }
.wiki-sidebar { position:sticky; top:90px; margin-top:0; align-self:start; background:var(--page); border:1px solid var(--line); border-radius:8px; box-shadow:var(--shadow); padding:12px; max-height:calc(100vh - 124px); overflow:auto; }
.wiki-sidebar-title { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; margin:2px 4px 8px; }
.wiki-sidebar a { display:block; padding:7px 8px; border-radius:6px; color:var(--ink); font-size:13px; }
.wiki-sidebar a:hover { background:var(--soft); text-decoration:none; }
.wiki-main { min-width:0; }
.grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin-top:14px; }
.card { background:var(--page); border:1px solid var(--line); border-radius:8px; padding:14px; box-shadow:var(--shadow); }
.metric-label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
.metric-value { font-size:21px; font-weight:750; margin-top:4px; }
.badge { display:inline-flex; align-items:center; border-radius:4px; padding:3px 7px; color:white; font-size:12px; font-weight:700; white-space:nowrap; }
.concern-clean,.concern-low { background:var(--low); } .concern-medium { background:var(--medium); } .concern-high { background:var(--high); } .concern-critical { background:var(--critical); }
.sev-info { background:var(--info); } .sev-low { background:var(--low); } .sev-medium { background:var(--medium); } .sev-high { background:var(--high); } .sev-critical { background:var(--critical); }
section { margin-top:18px; scroll-margin-top:96px; }
section h2 { margin:0 0 10px; font-size:22px; padding-bottom:6px; border-bottom:1px solid var(--line); }
.notice { border:1px solid var(--line); border-left:4px solid var(--info); background:var(--page); padding:13px 15px; border-radius:8px; color:#243447; box-shadow:var(--shadow); }
.redaction-banner { border-left-color:var(--medium); background:#fff7ed; margin-bottom:18px; }
.verdict { background:var(--page); border:1px solid var(--line); border-left:6px solid #64748b; border-radius:8px; padding:18px; box-shadow:var(--shadow); }
.verdict-clean,.verdict-low { border-left-color:var(--low); } .verdict-medium { border-left-color:var(--medium); } .verdict-high { border-left-color:var(--high); } .verdict-critical { border-left-color:var(--critical); }
.verdict-title { font-size:26px; font-weight:850; margin-top:4px; }
.verdict-summary { margin-top:7px; color:#334155; }
table { width:100%; border-collapse:collapse; background:var(--page); border:1px solid var(--line); border-radius:8px; overflow:hidden; box-shadow:var(--shadow); }
th,td { border-bottom:1px solid var(--line); padding:9px 10px; text-align:left; vertical-align:top; white-space:pre-wrap; word-break:break-word; }
th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.05em; background:var(--soft2); }
tr:last-child td { border-bottom:none; }
tr:hover td { background:#fbfdff; }
.finding-title { font-weight:700; margin-bottom:4px; }
.finding-details { color:#334155; white-space:pre-wrap; word-break:break-word; }
.muted { color:#334155; font-size:13px; margin-top:4px; }
.small { font-size:12px; color:var(--muted); }
.mono, code { font-family:Consolas,Cascadia Mono,monospace; font-size:12px; word-break:break-all; color:#1f2933; }
details { background:var(--page); border:1px solid var(--line); border-radius:8px; padding:12px 14px; margin-top:10px; box-shadow:var(--shadow); }
details details { box-shadow:none; margin:10px 0 0; background:var(--soft2); }
summary { cursor:pointer; font-weight:750; }
.summary-meta { color:var(--muted); font-size:12px; font-weight:400; margin-left:6px; }
.footer { margin-top:24px; color:var(--muted); font-size:12px; border-top:1px solid var(--line); padding-top:12px; }
.search-hidden { display:none !important; }
.no-search-results { display:none; background:#fff; border:1px dashed var(--line); border-radius:8px; padding:16px; color:var(--muted); margin-top:12px; }
body.searching .no-search-results.show { display:block; }
@media (max-width:1050px) { .wiki-layout { grid-template-columns:1fr; } .wiki-sidebar { position:relative; top:0; margin-top:0; max-height:none; } .grid { grid-template-columns:repeat(2,minmax(0,1fr)); } }
@media (max-width:650px) { .wiki-topbar-inner { display:block; } .wiki-search { margin-top:10px; } .grid { grid-template-columns:1fr; } table { display:block; overflow-x:auto; } }
";
        }

        private static string SearchScript()
        {
            return @"<script>
(function(){
  const input = document.getElementById('wikiSearch');
  const help = document.getElementById('searchHelp');
  const empty = document.getElementById('noSearchResults');
  if (!input) return;
  const items = Array.from(document.querySelectorAll('tbody tr, .card, .notice, .verdict'));
  const allDetails = Array.from(document.querySelectorAll('details'));
  function setOpenForMatch(el) {
    let parent = el.parentElement;
    while (parent) {
      if (parent.tagName && parent.tagName.toLowerCase() === 'details') parent.open = true;
      parent = parent.parentElement;
    }
  }
  function applySearch() {
    const q = input.value.trim().toLowerCase();
    document.body.classList.toggle('searching', q.length > 0);
    let matches = 0;
    if (!q) {
      items.forEach(el => el.classList.remove('search-hidden'));
      if (help) help.textContent = 'Search filters visible rows and opens matching sections.';
      if (empty) empty.classList.remove('show');
      return;
    }
    allDetails.forEach(d => d.open = true);
    items.forEach(el => {
      const hit = (el.textContent || '').toLowerCase().includes(q);
      el.classList.toggle('search-hidden', !hit);
      if (hit) { matches++; setOpenForMatch(el); }
    });
    if (help) help.textContent = matches + ' matching item' + (matches === 1 ? '' : 's') + ' shown.';
    if (empty) empty.classList.toggle('show', matches === 0);
  }
  input.addEventListener('input', applySearch);
  input.addEventListener('keydown', function(e){ if(e.key === 'Escape'){ input.value=''; applySearch(); input.blur(); } });
})();
</script>";
        }

        private sealed class Redactor
        {
            private readonly bool _enabled;
            private readonly string _user;
            private readonly string _computer;

            public Redactor(ReportIntegrityContext context, bool enabled)
            {
                _enabled = enabled;
                _user = context?.UserName ?? "";
                _computer = context?.ComputerName ?? "";
            }

            public string Text(string value)
            {
                if (!_enabled || string.IsNullOrEmpty(value)) return value ?? "";
                string v = value;
                if (!string.IsNullOrWhiteSpace(_user)) v = ReplaceInsensitive(v, _user, "<REDACTED_USER>");
                if (!string.IsNullOrWhiteSpace(_computer)) v = ReplaceInsensitive(v, _computer, "<REDACTED_COMPUTER>");
                v = System.Text.RegularExpressions.Regex.Replace(v, @"[0-9A-Fa-f]{2}([-:])[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}", "<REDACTED_MAC>");
                v = System.Text.RegularExpressions.Regex.Replace(v, @"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b", "<REDACTED_UUID>");
                v = System.Text.RegularExpressions.Regex.Replace(v, @"((SerialNumber|IdentifyingNumber|UUID)\s*=\s*')([^']*)(')", "$1<REDACTED_HARDWARE_ID>$4", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                v = System.Text.RegularExpressions.Regex.Replace(v, "USB(STOR)?\\\\[^\\s\"']+", "<REDACTED_USB_DEVICE_ID>");
                return v;
            }

            public string Path(string value)
            {
                if (!_enabled || string.IsNullOrEmpty(value)) return value ?? "";
                string v = Text(value);
                v = System.Text.RegularExpressions.Regex.Replace(v, @"[A-Za-z]:\\Users\\[^\\\r\n]+", m =>
                {
                    string s = m.Value;
                    int idx = s.IndexOf('\\', @"C:\Users\".Length);
                    return idx > 0 ? @"<REDACTED_USERPROFILE>" + s.Substring(idx) : "<REDACTED_USERPROFILE>";
                }, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                return v;
            }

            public string HardwareValue(string name, string value)
            {
                if (!_enabled || string.IsNullOrEmpty(value)) return value ?? "";
                string n = (name ?? "").ToLowerInvariant();
                if (n.Contains("serial") || n.Contains("uuid") || n.Contains("identifyingnumber") || n.Contains("macaddress")) return "<REDACTED_HARDWARE_ID>";
                return Text(value);
            }

            public string DeviceId(string value)
            {
                if (!_enabled || string.IsNullOrEmpty(value)) return value ?? "";
                return "<REDACTED_DEVICE_ID>";
            }

            private static string ReplaceInsensitive(string input, string needle, string replacement)
            {
                return System.Text.RegularExpressions.Regex.Replace(input, System.Text.RegularExpressions.Regex.Escape(needle), replacement, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            }
        }
    }
}
