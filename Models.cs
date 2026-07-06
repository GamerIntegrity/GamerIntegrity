using System;
using System.Collections.Generic;

namespace GamerIntegrity
{
    public enum Severity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    public sealed class Finding
    {
        public string Category { get; set; } = "";
        public string Title { get; set; } = "";
        public string Details { get; set; } = "";
        public Severity Severity { get; set; }
        public int Confidence { get; set; }
        public int Score { get; set; }
    }

    public sealed class ScanReport
    {
        public List<Finding> Findings { get; } = new List<Finding>();
        public List<ScanLimitation> Limitations { get; } = new List<ScanLimitation>();
        public int RawScore { get; set; }

        public void AddFinding(string category, string title, string details, Severity severity, int confidence, int score)
        {
            Findings.Add(new Finding
            {
                Category = category ?? "",
                Title = title ?? "",
                Details = details ?? "",
                Severity = severity,
                Confidence = ScannerHelpers.Clamp(confidence, 0, 100),
                Score = Math.Max(0, score)
            });
            RawScore += Math.Max(0, score);
        }

        public void AddLimitation(string source, string scope, string path, string message, Severity severity = Severity.Low)
        {
            string safeSource = source ?? "";
            string safeScope = scope ?? "";
            string safePath = path ?? "";
            string safeMessage = message ?? "";
            foreach (var existing in Limitations)
            {
                if (string.Equals(existing.Source, safeSource, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(existing.Scope, safeScope, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(existing.Path, safePath, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(existing.Message, safeMessage, StringComparison.OrdinalIgnoreCase)) return;
            }
            Limitations.Add(new ScanLimitation
            {
                Source = safeSource,
                Scope = safeScope,
                Path = safePath,
                Message = safeMessage,
                Severity = severity,
                When = ScannerHelpers.CurrentLocalTimestamp()
            });
        }
    }

    public sealed class ScanLimitation
    {
        public string Source { get; set; } = "";
        public string Scope { get; set; } = "";
        public string Path { get; set; } = "";
        public string Message { get; set; } = "";
        public Severity Severity { get; set; } = Severity.Low;
        public string When { get; set; } = "";
    }

    public sealed class CategoryScoreBreakdown
    {
        public string Category { get; set; } = "";
        public double RawPoints { get; set; }
        public double AdjustedPoints { get; set; }
        public int FindingCount { get; set; }
        public Severity MaxSeverity { get; set; } = Severity.Info;
        public int MaxConfidence { get; set; }
        public string StrongestFinding { get; set; } = "";
    }

    public sealed class ScoreAssessment
    {
        public int NormalizedScore { get; set; }
        public int RawEvidencePoints { get; set; }
        public int ReportConfidence { get; set; }
        public string ConcernLevel { get; set; } = "Low";
        public string Rationale { get; set; } = "";
        public List<CategoryScoreBreakdown> Categories { get; } = new List<CategoryScoreBreakdown>();
        public List<string> TopFactors { get; } = new List<string>();
    }

    public sealed class VerdictAssessment
    {
        public string Label { get; set; } = "No strong cheat evidence found";
        public string Level { get; set; } = "clean";
        public string Summary { get; set; } = "";
        public string Basis { get; set; } = "";
        public string Recommendation { get; set; } = "";
    }

    public sealed class ReportIntegrityContext
    {
        public string ReportId { get; set; } = "";
        public string ScanStartTime { get; set; } = "";
        public string ScanEndTime { get; set; } = "";
        public string ComputerName { get; set; } = "";
        public string UserName { get; set; } = "";
        public string ScannerVersion { get; set; } = "";
        public string ManifestPath { get; set; } = "";
    }

    public sealed class ScanOptions
    {
        public bool IncludeFileNameScan { get; set; } = true;
        public bool WriteReports { get; set; } = false;
        public string OutputDirectory { get; set; } = ".";
    }

    public sealed class ScanProgress
    {
        public int Percent { get; set; }
        public string Stage { get; set; } = "";
    }

    public sealed class ScanResult
    {
        public int ExitCode { get; set; }
        public string OutputDirectory { get; set; } = "";
        public string HtmlReportPath { get; set; } = "";
        public string JsonReportPath { get; set; } = "";
        public string RedactedHtmlReportPath { get; set; } = "";
        public string RedactedJsonReportPath { get; set; } = "";
        public string IntegrityManifestPath { get; set; } = "";
        public string RedactedIntegrityManifestPath { get; set; } = "";
        public string HtmlReportContent { get; set; } = "";
        public string JsonReportContent { get; set; } = "";
        public string RedactedHtmlReportContent { get; set; } = "";
        public string RedactedJsonReportContent { get; set; } = "";
        public ReportIntegrityContext IntegrityContext { get; set; }
        public ReportIntegrityContext RedactedIntegrityContext { get; set; }
        public string SummaryText { get; set; } = "";
    }

    public sealed class FileNameRule
    {
        public string Token { get; set; } = "";
        public string Category { get; set; } = "";
        public string Label { get; set; } = "";
        public Severity Severity { get; set; }
        public int Confidence { get; set; }
        public int Score { get; set; }
    }

    public sealed class FileNameMatch
    {
        public string Path { get; set; } = "";
        public string Token { get; set; } = "";
        public string Category { get; set; } = "";
        public string Label { get; set; } = "";
        public Severity Severity { get; set; }
        public int Confidence { get; set; }
        public int Score { get; set; }
        public string LastWriteTime { get; set; } = "";
    }

    public sealed class BrowserHistoryMatch
    {
        public string Browser { get; set; } = "";
        public string Profile { get; set; } = "";
        public string HistoryPath { get; set; } = "";
        public string Token { get; set; } = "";
        public string Label { get; set; } = "";
        public string Snippet { get; set; } = "";
        public string When { get; set; } = "";
        public string TimeType { get; set; } = "";
        public Severity Severity { get; set; }
        public int Confidence { get; set; }
        public int Score { get; set; }
    }

    public sealed class BrowserHistorySource
    {
        public string Browser { get; set; } = "";
        public string Profile { get; set; } = "";
        public string HistoryPath { get; set; } = "";
        public string StoreType { get; set; } = "";
    }

    public sealed class ExecutionArtifact
    {
        public string Source { get; set; } = "";
        public string Name { get; set; } = "";
        public string Path { get; set; } = "";
        public string Token { get; set; } = "";
        public string Label { get; set; } = "";
        public string When { get; set; } = "";
        public string Details { get; set; } = "";
        public Severity Severity { get; set; } = Severity.Info;
        public int Confidence { get; set; }
        public int Score { get; set; }
    }

    public sealed class BrowserDownloadMatch
    {
        public string Browser { get; set; } = "";
        public string Profile { get; set; } = "";
        public string HistoryPath { get; set; } = "";
        public string Token { get; set; } = "";
        public string Label { get; set; } = "";
        public string Url { get; set; } = "";
        public string Domain { get; set; } = "";
        public string LocalPath { get; set; } = "";
        public string EvidenceType { get; set; } = "";
        public string Snippet { get; set; } = "";
        public string When { get; set; } = "";
        public string TimeType { get; set; } = "";
        public Severity Severity { get; set; } = Severity.Info;
        public int Confidence { get; set; }
        public int Score { get; set; }
    }

    public sealed class BrowserScanResult
    {
        public List<BrowserHistorySource> Sources { get; } = new List<BrowserHistorySource>();
        public List<BrowserHistoryMatch> HistoryMatches { get; } = new List<BrowserHistoryMatch>();
        public List<BrowserDownloadMatch> DownloadMatches { get; } = new List<BrowserDownloadMatch>();
    }

    public sealed class RuntimeArtifact
    {
        public string SourceType { get; set; } = "";
        public string Name { get; set; } = "";
        public string Path { get; set; } = "";
        public string Token { get; set; } = "";
        public string Label { get; set; } = "";
        public string Details { get; set; } = "";
        public string When { get; set; } = "";
        public Severity Severity { get; set; } = Severity.Info;
        public int Confidence { get; set; }
        public int Score { get; set; }
    }

    public sealed class SourceProjectSummary
    {
        public string Root { get; set; } = "";
        public bool GeneratedStructure { get; set; }
        public int TotalDetections { get; set; }
        public int DirectSourceCount { get; set; }
        public int ProjectFileCount { get; set; }
        public int BuildArtifactCount { get; set; }
        public int MapperCount { get; set; }
        public int InjectorSpooferTraceCount { get; set; }
        public int MaxConfidence { get; set; }
        public int MaxScore { get; set; }
        public Severity MaxSeverity { get; set; } = Severity.Info;
        public HashSet<string> Tokens { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Labels { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public List<string> Samples { get; } = new List<string>();
        public string Determination { get; set; } = "";
    }

    public sealed class CheatingTimelineEvent
    {
        public string When { get; set; } = "";
        public string EventType { get; set; } = "";
        public string Source { get; set; } = "";
        public string Summary { get; set; } = "";
        public string Evidence { get; set; } = "";
        public string TimeType { get; set; } = "";
        public Severity Severity { get; set; } = Severity.Info;
        public int Confidence { get; set; }
    }

    public sealed class HardwareRecord
    {
        public string Category { get; set; } = "";
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public string Source { get; set; } = "";
    }

    public sealed class DeviceConnectionRecord
    {
        public string Enumerator { get; set; } = "";
        public string DeviceId { get; set; } = "";
        public string Description { get; set; } = "";
        public string Manufacturer { get; set; } = "";
        public string Service { get; set; } = "";
        public string ClassName { get; set; } = "";
        public string Location { get; set; } = "";
        public string FirstInstallTime { get; set; } = "";
        public string InstallTime { get; set; } = "";
        public string LastArrivalTime { get; set; } = "";
        public string LastRemovalTime { get; set; } = "";
        public bool CurrentlyPresent { get; set; }
        public bool MassStorage { get; set; }
        public string Source { get; set; } = "";
    }



    public sealed class DmaDeviceRecord
    {
        public string Enumerator { get; set; } = "";
        public string DeviceId { get; set; } = "";
        public string Name { get; set; } = "";
        public string Manufacturer { get; set; } = "";
        public string Service { get; set; } = "";
        public string ClassName { get; set; } = "";
        public string ClassGuid { get; set; } = "";
        public string Location { get; set; } = "";
        public string HardwareIds { get; set; } = "";
        public string CompatibleIds { get; set; } = "";
        public string FirstInstallTime { get; set; } = "";
        public string InstallTime { get; set; } = "";
        public string LastArrivalTime { get; set; } = "";
        public string LastRemovalTime { get; set; } = "";
        public bool CurrentlyPresent { get; set; }
        public string Source { get; set; } = "";
        public string ReviewReason { get; set; } = "";
        public Severity Severity { get; set; } = Severity.Info;
        public int Confidence { get; set; }
    }

    public sealed class DriverServiceInfo
    {
        public string ServiceName { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string BinaryPath { get; set; } = "";
        public string StartType { get; set; } = "";
        public string CurrentState { get; set; } = "";
    }

    public sealed class DriverInfo
    {
        public string Name { get; set; } = "";
        public string RawPath { get; set; } = "";
        public string Path { get; set; } = "";
        public string Company { get; set; } = "";
        public string ProductName { get; set; } = "";
        public string OriginalFileName { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public bool FileExists { get; set; }
        public bool WindowsSystemPath { get; set; }
        public bool SignedTrusted { get; set; }
        public bool SuspiciousNamePattern { get; set; }
        public bool KnownVulnerableDriver { get; set; }
        public string KnownVulnerableDriverId { get; set; } = "";
        public string KnownVulnerableDriverName { get; set; } = "";
        public string KnownVulnerableDriverMatch { get; set; } = "";
        public string KnownVulnerableDriverReason { get; set; } = "";
        public Severity KnownVulnerableDriverSeverity { get; set; } = Severity.Info;
        public int KnownVulnerableDriverConfidence { get; set; }
        public DriverServiceInfo Service { get; set; }
    }
}
