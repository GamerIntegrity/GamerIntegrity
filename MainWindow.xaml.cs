using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Input;
using System.Windows.Threading;

namespace GamerIntegrity
{
    public partial class MainWindow : Window
    {
        private readonly ReportWorkspaceViewModel _workspace = new ReportWorkspaceViewModel();

        private string _scanOutputDirectory;
        private string _htmlReportPath;
        private string _jsonReportPath;
        private string _redactedHtmlReportPath;
        private string _redactedJsonReportPath;
        private ScanResult _lastScanResult;
        private bool _sidebarShown;
        private string _lastDisplayedProgressStage = string.Empty;
        private readonly DispatcherTimer _searchDebounceTimer;

        public MainWindow()
        {
            InitializeComponent();
            DataContext = _workspace;

            _searchDebounceTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(180) };
            _searchDebounceTimer.Tick += delegate
            {
                _searchDebounceTimer.Stop();
                ApplyFilter();
            };

            HideSidebarNow();

            Loaded += MainWindow_Loaded;
            SizeChanged += MainWindow_SizeChanged;
            KeyDown += MainWindow_KeyDown;

            if (!IsRunningAsAdministrator())
            {
                ShowAdminGate();
            }
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            UpdateSearchPanelWidth();
            UpdateScanLayoutHeight();
        }

        private void MainWindow_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            UpdateSearchPanelWidth();
            UpdateScanLayoutHeight();
        }

        private async void RunScanButton_Click(object sender, RoutedEventArgs e)
        {
            await StartScanAsync();
        }

        private async Task StartScanAsync()
        {
            _scanOutputDirectory = Path.Combine(AppContext.BaseDirectory, "Reports", DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture));
            _htmlReportPath = Path.Combine(_scanOutputDirectory, "GamerIntegrity_Report.html");
            _jsonReportPath = Path.Combine(_scanOutputDirectory, "GamerIntegrity_Report.json");
            _redactedHtmlReportPath = Path.Combine(_scanOutputDirectory, "GamerIntegrity_Report_Redacted.html");
            _redactedJsonReportPath = Path.Combine(_scanOutputDirectory, "GamerIntegrity_Report_Redacted.json");

            PrepareForScan();
            AppendLog("Starting GamerIntegrity scan.");
            AppendLog("Results stay inside the app until you export them.");

            var progress = new Progress<ScanProgress>(p => UpdateProgress(p.Percent, p.Stage));
            ScanResult result = null;

            try
            {
                result = await Task.Run(() => ScannerService.Run(new ScanOptions
                {
                    IncludeFileNameScan = true,
                    WriteReports = false,
                    OutputDirectory = _scanOutputDirectory
                }, progress));
            }
            catch (Exception ex)
            {
                AppendLog("Scanner error: " + ex.Message);
                result = new ScanResult { ExitCode = 3, OutputDirectory = _scanOutputDirectory, SummaryText = ex.Message };
            }

            FinishScan(result);
        }

        private void PrepareForScan()
        {
            RunScanButton.IsEnabled = false;
            SearchPanel.Visibility = Visibility.Collapsed;
            SearchBox.Text = string.Empty;
            LogBox.Clear();

            _lastScanResult = null;
            HideSidebarNow();
            OverviewSection.Visibility = Visibility.Collapsed;
            ScanningSection.Visibility = Visibility.Visible;
            ActivitySection.Visibility = Visibility.Visible;
            ReportChoicePanel.Visibility = Visibility.Collapsed;
            ResultsSection.Visibility = Visibility.Collapsed;
            ResultsSection.Opacity = 0;
            ScanProgressBar.BeginAnimation(RangeBase.ValueProperty, null);
            ScanProgressBar.Value = 0;
            ProgressPercentText.Text = "0%";
            ProgressCategoryText.Text = "Offline scan starting";
            ProgressStageText.Text = "Getting scan ready...";
            ProgressSubText.Text = "GamerIntegrity is preparing an offline-only check. Nothing is uploaded.";
            ProgressTipText.Text = "Do not close this window";
            _lastDisplayedProgressStage = string.Empty;

            _workspace.Reset();
            ArticleScroll.ScrollToTop();
            Dispatcher.BeginInvoke(new Action(UpdateScanLayoutHeight), DispatcherPriority.Background);
        }

        private void UpdateProgress(int percent, string stage)
        {
            int safePercent = Math.Max(0, Math.Min(100, percent));
            AnimateProgressTo(safePercent);
            ProgressPercentText.Text = safePercent.ToString(CultureInfo.InvariantCulture) + "%";

            var status = BuildScanStatus(safePercent, stage);
            ProgressCategoryText.Text = status.Category;
            ProgressStageText.Text = status.Title;
            ProgressSubText.Text = status.Detail;
            ProgressTipText.Text = status.Tip;

            if (!string.IsNullOrWhiteSpace(status.LogMessage) && !string.Equals(_lastDisplayedProgressStage, status.LogMessage, StringComparison.Ordinal))
            {
                _lastDisplayedProgressStage = status.LogMessage;
                AppendLog(status.LogMessage);
            }
        }

        private void AnimateProgressTo(int percent)
        {
            double currentValue = ScanProgressBar.Value;
            ScanProgressBar.BeginAnimation(RangeBase.ValueProperty, null);

            if (Math.Abs(currentValue - percent) < 0.1)
            {
                ScanProgressBar.Value = percent;
                return;
            }

            var animation = new DoubleAnimation(currentValue, percent, TimeSpan.FromMilliseconds(460))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
                FillBehavior = FillBehavior.Stop
            };
            animation.Completed += delegate { ScanProgressBar.Value = percent; };
            ScanProgressBar.BeginAnimation(RangeBase.ValueProperty, animation, HandoffBehavior.SnapshotAndReplace);
        }

        private ScanStatusText BuildScanStatus(int percent, string rawStage)
        {
            string stage = (rawStage ?? string.Empty).Trim();
            string lower = stage.ToLowerInvariant();
            string countText = ExtractCountText(stage);

            if (percent >= 100)
            {
                return new ScanStatusText("Scan complete", "Scan complete", "Choose Redacted for sharing or Non-Redacted for the full local view.", "Ready to review", "Scan complete. Choose a report view.");
            }
            if (lower.Contains("getting") || lower.Contains("starting") || percent < 8)
            {
                return new ScanStatusText("Offline scan starting", "Getting the scan ready", "Preparing folders, permissions, and offline report memory. Nothing is uploaded.", "Offline only", "Getting the scan ready...");
            }
            if (lower.Contains("windows") || lower.Contains("compatibility"))
            {
                return new ScanStatusText("System check", "Checking Windows and admin access", "Confirming the scan can read the Windows areas needed for a complete local report.", "System details", stage);
            }
            if (lower.Contains("network") || lower.Contains("display"))
            {
                return new ScanStatusText("System inventory", "Reading hardware basics", "Capturing display and network inventory so the report has useful PC context.", "Inventory", stage);
            }
            if (lower.Contains("security center") || lower.Contains("antivirus"))
            {
                return new ScanStatusText("Security check", "Checking Windows Security status", "Reading local antivirus/security state. This helps explain what protection was visible during the scan.", "Windows Security", stage);
            }
            if (lower.Contains("secure boot") || lower.Contains("tpm") || lower.Contains("bcd") || lower.Contains("boot security") || lower.Contains("driver-blocklist"))
            {
                return new ScanStatusText("Boot security", "Checking boot and driver safety settings", "Looking at Secure Boot, TPM, kernel settings, and vulnerable-driver protections.", "Boot checks", stage);
            }
            if (lower.Contains("installed program") || lower.Contains("installed tool"))
            {
                return new ScanStatusText("Installed tools", "Checking installed tools", "Looking for installed cheat tools, injectors, debuggers, decompilers, and process-inspection apps." + countText, "Programs", stage);
            }
            if (lower.Contains("amcache") || lower.Contains("prefetch") || lower.Contains("execution") || lower.Contains("launch trace"))
            {
                return new ScanStatusText("Launch evidence", "Checking launch traces", "Looking for signs that suspicious tools were opened, not just downloaded." + countText, "High value", stage);
            }
            if (lower.Contains("running") || lower.Contains("startup") || lower.Contains("runtime") || lower.Contains("scheduled") || lower.Contains("service"))
            {
                return new ScanStatusText("Usage traces", "Checking startup and recent app activity", "Reviewing processes, services, tasks, startup entries, and retained usage traces." + countText, "Usage history", stage);
            }
            if (lower.Contains("driver"))
            {
                return new ScanStatusText("Driver review", "Checking driver inventory", "Reading local driver/service records and signatures so suspicious driver context can stand out." + countText, "Drivers", stage);
            }
            if (lower.Contains("dma") || lower.Contains("pcie") || lower.Contains("pci/") || lower.Contains("thunderbolt") || lower.Contains("usb4"))
            {
                return new ScanStatusText("DMA / PCIe review", "Checking DMA-capable hardware context", "Reviewing PCIe, Thunderbolt, USB4, CFexpress, FPGA/DMA-adjacent, and SetupAPI device records for context." + countText, "Hardware review", stage);
            }
            if (lower.Contains("hardware") || lower.Contains("bios") || lower.Contains("disk") || lower.Contains("identity"))
            {
                return new ScanStatusText("Hardware identity", "Capturing hardware identity records", "Collecting local board, BIOS, disk, and network-adapter identifiers for review context." + countText, "Hardware", stage);
            }
            if (lower.Contains("usb") || lower.Contains("external-device") || lower.Contains("external device"))
            {
                return new ScanStatusText("External devices", "Checking USB device history", "Reviewing local USB and USB-storage connection records." + countText, "Devices", stage);
            }
            if (lower.Contains("browser"))
            {
                return new ScanStatusText("Browser evidence", "Checking local browser history and downloads", "Looking for cheat-provider domains, source/download records, and related search/download traces." + countText, "Browser", stage);
            }
            if (lower.Contains("file/folder") || lower.Contains("file name") || lower.Contains("folders"))
            {
                return new ScanStatusText("Files and folders", "Checking common user folders", "Scanning Desktop, Downloads, Documents, repos, and project folders for cheat/source/build names." + countText, "Files", stage);
            }
            if (lower.Contains("grouping") || lower.Contains("timeline"))
            {
                return new ScanStatusText("Report building", "Grouping evidence into readable sections", "Combining related hits so staff can review projects, launches, downloads, and browser evidence more clearly.", "Organizing", stage);
            }
            if (lower.Contains("preparing") || lower.Contains("report"))
            {
                return new ScanStatusText("Report building", "Preparing the in-app report", "Building the local report view and redacted/non-redacted options.", "Almost done", stage);
            }

            return new ScanStatusText("Offline scan running", string.IsNullOrWhiteSpace(stage) ? "Scanning local PC traces" : stage, "GamerIntegrity is checking local Windows, browser, device, and file traces.", "Offline only", stage);
        }

        private static string ExtractCountText(string stage)
        {
            if (string.IsNullOrWhiteSpace(stage))
                return string.Empty;

            int colon = stage.IndexOf(':');
            if (colon >= 0 && colon + 1 < stage.Length)
            {
                string tail = stage.Substring(colon + 1).Trim();
                if (!string.IsNullOrWhiteSpace(tail))
                    return " Current result: " + tail;
            }

            return string.Empty;
        }

        private void FinishScan(ScanResult result)
        {
            if (result == null)
            {
                result = new ScanResult { ExitCode = 3, OutputDirectory = _scanOutputDirectory };
            }

            _lastScanResult = result;
            _htmlReportPath = FirstNonBlank(result.HtmlReportPath, _htmlReportPath);
            _jsonReportPath = FirstNonBlank(result.JsonReportPath, _jsonReportPath);
            _redactedHtmlReportPath = FirstNonBlank(result.RedactedHtmlReportPath, _redactedHtmlReportPath);
            _redactedJsonReportPath = FirstNonBlank(result.RedactedJsonReportPath, _redactedJsonReportPath);
            _scanOutputDirectory = FirstNonBlank(result.OutputDirectory, _scanOutputDirectory);

            if (!string.IsNullOrWhiteSpace(result.SummaryText))
            {
                AppendLog(result.SummaryText.Trim());
            }

            RunScanButton.IsEnabled = true;

            if (result.ExitCode == 0)
            {
                UpdateProgress(100, "Scan complete. Choose Redacted or Non-Redacted to view results.");
                ReportChoicePanel.Visibility = Visibility.Visible;
                ActivitySection.Visibility = Visibility.Collapsed;
                AppendLog("Scan complete. Waiting for Redacted or Non-Redacted view choice.");
                return;
            }

            ProgressCategoryText.Text = result.ExitCode == 2 ? "Report issue" : "Scan failed";
            ProgressStageText.Text = result.ExitCode == 2
                ? "Scan finished, but results could not be prepared."
                : "Scan failed.";
            ProgressSubText.Text = result.ExitCode == 2
                ? "The scanner finished, but the in-app report could not be prepared. Try running as administrator and check Windows security blocks."
                : "The scan stopped before a report could be completed. Try running as administrator and check whether Windows security blocked access.";
            ProgressTipText.Text = "Review the message";

            if (result.ExitCode == 2)
            {
                ShowError("Results Error", "The scan ran, but the in-app results could not be prepared. Try running GamerIntegrity.exe as administrator and check whether Windows security blocked access.");
            }
            else
            {
                ShowError("Scan Failed", "The scan failed before results were completed. Try running GamerIntegrity.exe as administrator. If it still fails, Windows security may be blocking access to PC data.");
            }
        }

        private void FadeInResults()
        {
            OverviewSection.Visibility = Visibility.Collapsed;
            ActivitySection.Visibility = Visibility.Collapsed;
            ReportChoicePanel.Visibility = Visibility.Collapsed;
            ScanningSection.Visibility = Visibility.Collapsed;
            SearchPanel.Visibility = Visibility.Visible;
            ShowSidebarWithSlide();
            ResultsSection.Visibility = Visibility.Visible;
            ResultsSection.Opacity = 0;
            SetActiveNav(NavResult);

            ArticleScroll.UpdateLayout();
            UpdateSearchPanelWidth();
            Dispatcher.BeginInvoke(new Action(UpdateSearchPanelWidth), DispatcherPriority.Background);
            ArticleScroll.ScrollToTop();
            Dispatcher.BeginInvoke(new Action(() => ArticleScroll.ScrollToTop()), DispatcherPriority.Background);

            var animation = new DoubleAnimation
            {
                From = 0,
                To = 1,
                Duration = TimeSpan.FromMilliseconds(420),
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
            };

            ResultsSection.BeginAnimation(OpacityProperty, animation);
        }

        private void HideSidebarNow()
        {
            _sidebarShown = false;
            LeftSidebarColumn.Width = new GridLength(0);
            SidebarPanel.BeginAnimation(OpacityProperty, null);
            SidebarSlideTransform.BeginAnimation(TranslateTransform.XProperty, null);
            SidebarSlideTransform.X = -268;
            SidebarPanel.Opacity = 0;
            SidebarPanel.Visibility = Visibility.Collapsed;
        }

        private void ShowSidebarWithSlide()
        {
            if (_sidebarShown)
            {
                return;
            }

            _sidebarShown = true;
            LeftSidebarColumn.Width = new GridLength(268);
            SidebarPanel.Visibility = Visibility.Visible;
            SidebarPanel.Opacity = 0;
            SidebarSlideTransform.X = -268;

            var fade = new DoubleAnimation
            {
                From = 0,
                To = 1,
                Duration = TimeSpan.FromMilliseconds(300),
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
            };

            var slide = new DoubleAnimation
            {
                From = -268,
                To = 0,
                Duration = TimeSpan.FromMilliseconds(340),
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
            };

            SidebarPanel.BeginAnimation(OpacityProperty, fade);
            SidebarSlideTransform.BeginAnimation(TranslateTransform.XProperty, slide);

            Dispatcher.BeginInvoke(new Action(UpdateSearchPanelWidth), DispatcherPriority.Background);
        }

        private void UpdateSearchPanelWidth()
        {
            if (SearchPanel == null || ArticlePageBorder == null || TopBarLayout == null)
            {
                return;
            }

            if (SearchPanel.Visibility != Visibility.Visible)
            {
                return;
            }

            try
            {
                Point articleLeftPoint = ArticlePageBorder.TransformToAncestor(this).Transform(new Point(0, 0));
                Point topBarLeftPoint = TopBarLayout.TransformToAncestor(this).Transform(new Point(0, 0));

                double githubColumnWidth = TopBarLayout.ColumnDefinitions.Count > 2
                    ? TopBarLayout.ColumnDefinitions[2].ActualWidth
                    : 0;

                double targetLeft = articleLeftPoint.X;
                double targetRight = topBarLeftPoint.X + TopBarLayout.ActualWidth - githubColumnWidth - SearchPanel.Margin.Right;
                double targetWidth = targetRight - targetLeft;

                if (double.IsNaN(targetWidth) || double.IsInfinity(targetWidth))
                {
                    return;
                }

                double availableColumnWidth = TopBarLayout.ColumnDefinitions.Count > 1
                    ? TopBarLayout.ColumnDefinitions[1].ActualWidth - SearchPanel.Margin.Left - SearchPanel.Margin.Right
                    : targetWidth;

                double safeWidth = Math.Max(280, Math.Min(targetWidth, availableColumnWidth));
                SearchPanel.Width = safeWidth;
            }
            catch
            {
            }
        }

        private void UpdateScanLayoutHeight()
        {
            if (ScanningSection == null || ArticleScroll == null)
            {
                return;
            }

            if (ScanningSection.Visibility != Visibility.Visible)
            {
                return;
            }

            double availableHeight = ArticleScroll.ActualHeight;
            if (double.IsNaN(availableHeight) || double.IsInfinity(availableHeight) || availableHeight <= 0)
            {
                return;
            }

            ScanningSection.Height = Math.Max(420, availableHeight - 44);
        }

        private void MainWindow_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Escape && ModalOverlay.Visibility == Visibility.Visible)
            {
                HideModal();
                e.Handled = true;
            }
        }

        private void LoadReportIntoView(string jsonContent)
        {
            _workspace.Reset();

            if (string.IsNullOrWhiteSpace(jsonContent))
            {
                _workspace.Verdict = "No scan data found";
                _workspace.VerdictBasis = "The scan completed, but the in-app results were not readable.";
                _workspace.Metrics.Add(new MetricItem("Status", "No data", "In-app view unavailable"));
                return;
            }

            try
            {
                using (var document = JsonDocument.Parse(jsonContent))
                {
                    JsonElement root = document.RootElement;
                    JsonElement summary;
                    if (TryGetObject(root, "summary", out summary))
                    {
                        _workspace.Verdict = GetString(summary, "verdict", "Scan report loaded");
                        _workspace.VerdictLevel = GetString(summary, "verdictLevel", "");
                        _workspace.VerdictBasis = GetString(summary, "verdictBasis", "Check the flags and traces below.");
                        string overallConcern = CleanConcernValue(GetString(summary, "overallConcern", "n/a"));
                        _workspace.OverallConcern = overallConcern;

                        _workspace.Metrics.Add(new MetricItem("Overall level", overallConcern, "How serious this looks"));
                        _workspace.Metrics.Add(new MetricItem("Signal strength", GetString(summary, "evidenceStrength", "0") + " / 100", "Higher means stronger detections"));
                        _workspace.Metrics.Add(new MetricItem("Scan confidence", GetString(summary, "scanConfidence", "0") + "%", "How reliable this result is"));
                        _workspace.Metrics.Add(new MetricItem("Points", GetString(summary, "rawSignalPoints", "0"), "Before score cap"));
                        _workspace.Metrics.Add(new MetricItem("Detections", GetString(summary, "findingCount", "0"), "Total matched items"));
                        _workspace.Metrics.Add(new MetricItem("Limitations", GetString(summary, "scanLimitations", "0"), "Failed/skipped reads"));
                        _workspace.Metrics.Add(new MetricItem("Launch", GetString(summary, "executionArtifacts", "0"), "AmCache / Prefetch"));
                        _workspace.Metrics.Add(new MetricItem("Downloads", GetString(summary, "browserSourceDownloadMatches", "0"), "History and download hits"));
                        _workspace.Metrics.Add(new MetricItem("DMA / PCIe", GetString(summary, "dmaPcieReviewRecords", "0"), "Hardware review context"));
                        _workspace.Metrics.Add(new MetricItem("Vuln drivers", GetString(summary, "knownVulnerableDriverMatches", "0"), GetString(summary, "knownVulnerableDriverCatalog", "Embedded catalog")));
                        _workspace.Metrics.Add(new MetricItem("Projects", GetString(summary, "sourceProjectGroups", "0"), "Grouped build/source hits"));
                    }
                    else
                    {
                        _workspace.Verdict = "Scan report loaded";
                        _workspace.VerdictBasis = "Summary data was not present, but scan rows were loaded.";
                    }

                    AddTimelineSection(root);
                    AddFindingsSection(root);
                    AddScanLimitationsSection(root);
                    AddSourceProjectSection(root);
                    AddExecutionSection(root);
                    AddBrowserDownloadSection(root);
                    AddRuntimeSection(root);
                    AddInstalledProgramsSection(root);
                    AddBrowserKeywordsSection(root);
                    AddFileNameSection(root);
                    AddDmaPcieSection(root);
                    AddExternalDevicesSection(root);
                    AddHardwareSection(root);
                    AddDriversSection(root);
                }

                ApplyFilter();
            }
            catch (Exception ex)
            {
                AppendLog("Could not load scan data into the app view: " + ex.Message);
                _workspace.Reset();
                _workspace.Verdict = "Scan view failed to load";
                _workspace.VerdictBasis = ex.Message;
                _workspace.Metrics.Add(new MetricItem("Status", "Error", "The in-app results could not be parsed."));
            }
        }

        private void AddTimelineSection(JsonElement root)
        {
            AddSection(root, "evidenceTimeline", "Timeline", "Dated and undated hits, newest first.", false, delegate(JsonElement item)
            {
                string when = FriendlyWhen(GetString(item, "when", ""));
                string eventType = GetString(item, "eventType", "Timeline event");
                string summary = GetString(item, "summary", "");
                string evidence = GetString(item, "evidence", "");
                string source = GetString(item, "source", "Timeline");
                string extra = JoinNonBlank("Time shown from: " + GetString(item, "timeType", ""), summary);

                return new EvidenceItem
                {
                    Section = "Timeline",
                    Severity = NormalizeSeverity(GetString(item, "severity", "Info")),
                    Title = eventType,
                    Source = source,
                    Detail = FirstNonBlank(evidence, summary),
                    Extra = extra,
                    When = when,
                    Confidence = GetInt(item, "confidence", 0),
                    Score = 0
                };
            });
        }

        private void AddFindingsSection(JsonElement root)
        {
            AddSection(root, "findings", "Detections", "Every scanner detection in the order it was found.", false, delegate(JsonElement item)
            {
                return new EvidenceItem
                {
                    Section = "Detections",
                    Severity = NormalizeSeverity(GetString(item, "severity", "Info")),
                    Title = GetString(item, "title", "Flag"),
                    Source = FirstNonBlank(GetString(item, "categoryLabel", ""), GetString(item, "category", "Flag")),
                    Detail = GetString(item, "details", ""),
                    Extra = "",
                    When = "",
                    Confidence = GetInt(item, "confidence", 0),
                    Score = GetInt(item, "score", 0)
                };
            });
        }

        private void AddScanLimitationsSection(JsonElement root)
        {
            AddSection(root, "scanLimitations", "Limitations", "Failed reads, skipped sources, and safety caps that affected scan coverage.", true, delegate(JsonElement item)
            {
                return new EvidenceItem
                {
                    Section = "Limitations",
                    Severity = NormalizeSeverity(GetString(item, "severity", "Low")),
                    Title = FirstNonBlank(GetString(item, "message", "Scan limitation"), "Scan limitation"),
                    Source = FirstNonBlank(GetString(item, "source", "Scan"), "Scan"),
                    Detail = GetString(item, "path", ""),
                    Extra = JoinNonBlank("Scope: " + GetString(item, "scope", ""), "Recorded: " + FriendlyWhen(GetString(item, "when", ""))),
                    When = FriendlyWhen(GetString(item, "when", "")),
                    Confidence = 0,
                    Score = 0
                };
            });
        }

        private void AddSourceProjectSection(JsonElement root)
        {
            AddSection(root, "sourceProjectGroups", "Projects", "Grouped source folders, project files, build artifacts, mapper traces, injector hits, and spoofer hits.", false, delegate(JsonElement item)
            {
                string labels = JoinArray(item, "labels");
                string tokens = JoinArray(item, "tokens");
                string samples = JoinArray(item, "samples");
                string extra = JoinNonBlank(
                    "Determination: " + GetString(item, "determination", ""),
                    "Labels: " + labels,
                    "Tokens: " + tokens,
                    "Samples: " + samples);

                return new EvidenceItem
                {
                    Section = "Projects",
                    Severity = NormalizeSeverity(GetString(item, "maxSeverity", "Info")),
                    Title = "Grouped cheat/build hit",
                    Source = GetString(item, "totalDetections", "0") + " hit(s)",
                    Detail = GetString(item, "root", ""),
                    Extra = extra,
                    When = "",
                    Confidence = GetInt(item, "maxConfidence", 0),
                    Score = GetInt(item, "maxScore", 0)
                };
            });
        }

        private void AddExecutionSection(JsonElement root)
        {
            AddSection(root, "executionArtifacts", "Launch", "Recently run files and Windows execution traces.", false, delegate(JsonElement item)
            {
                return new EvidenceItem
                {
                    Section = "Launch",
                    Severity = NormalizeSeverity(GetString(item, "severity", "Info")),
                    Title = FirstNonBlank(GetString(item, "label", ""), GetString(item, "name", "Launch trace")),
                    Source = GetString(item, "source", "Launch trace"),
                    Detail = FirstNonBlank(GetString(item, "path", ""), GetString(item, "name", "")),
                    Extra = JoinNonBlank(GetString(item, "details", ""), "Token: " + GetString(item, "token", "")),
                    When = FriendlyWhen(GetString(item, "when", "")),
                    Confidence = GetInt(item, "confidence", 0),
                    Score = GetInt(item, "score", 0)
                };
            });
        }

        private void AddBrowserDownloadSection(JsonElement root)
        {
            AddSection(root, "browserSourceDownloadMatches", "Downloads", "Browser URLs, local download paths, domains, and source records related to cheat tooling.", false, delegate(JsonElement item)
            {
                string browser = JoinNonBlank(GetString(item, "browser", ""), GetString(item, "profile", ""));
                string detail = JoinNonBlank(GetString(item, "url", ""), GetString(item, "localPath", ""));
                string extra = JoinNonBlank(
                    "Domain: " + GetString(item, "domain", ""),
                    "Type: " + GetString(item, "evidenceType", ""),
                    GetString(item, "snippet", ""));

                return new EvidenceItem
                {
                    Section = "Downloads",
                    Severity = NormalizeSeverity(GetString(item, "severity", "Info")),
                    Title = FirstNonBlank(GetString(item, "label", ""), "Download hit"),
                    Source = FirstNonBlank(browser, "Browser"),
                    Detail = detail,
                    Extra = extra,
                    When = FriendlyWhen(GetString(item, "when", "")),
                    Confidence = GetInt(item, "confidence", 0),
                    Score = GetInt(item, "score", 0)
                };
            });
        }

        private void AddRuntimeSection(JsonElement root)
        {
            AddSection(root, "runtimeArtifacts", "Startup", "Processes, services, run keys, startup entries, and scheduled task hits.", false, delegate(JsonElement item)
            {
                return new EvidenceItem
                {
                    Section = "Startup",
                    Severity = NormalizeSeverity(GetString(item, "severity", "Info")),
                    Title = FirstNonBlank(GetString(item, "label", ""), GetString(item, "name", "Startup trace")),
                    Source = GetString(item, "sourceType", "Runtime"),
                    Detail = FirstNonBlank(GetString(item, "path", ""), GetString(item, "name", "")),
                    Extra = JoinNonBlank(GetString(item, "details", ""), "Token: " + GetString(item, "token", "")),
                    When = FriendlyWhen(GetString(item, "when", "")),
                    Confidence = GetInt(item, "confidence", 0),
                    Score = GetInt(item, "score", 0)
                };
            });
        }

        private void AddInstalledProgramsSection(JsonElement root)
        {
            AddFileMatchSection(root, "installedProgramMatches", "Reversal", "Installed apps that matched configured cheat/tool rules.", false);
        }

        private void AddFileNameSection(JsonElement root)
        {
            AddFileMatchSection(root, "fileNameMatches", "Files / Folders", "File and folder name hits. Use context because name-only hits can be lower confidence.", false);
        }

        private void AddFileMatchSection(JsonElement root, string arrayName, string title, string description, bool expanded)
        {
            AddSection(root, arrayName, title, description, expanded, delegate(JsonElement item)
            {
                return new EvidenceItem
                {
                    Section = title,
                    Severity = NormalizeSeverity(GetString(item, "severity", "Info")),
                    Title = FirstNonBlank(GetString(item, "label", ""), "File/folder hit"),
                    Source = "Token: " + GetString(item, "token", ""),
                    Detail = GetString(item, "path", ""),
                    Extra = "Last write: " + GetString(item, "lastWriteTime", ""),
                    When = FriendlyWhen(GetString(item, "lastWriteTime", "")),
                    Confidence = GetInt(item, "confidence", 0),
                    Score = GetInt(item, "score", 0)
                };
            });
        }

        private void AddBrowserKeywordsSection(JsonElement root)
        {
            AddSection(root, "browserKeywordMatches", "Browser", "Browser history keyword hits with profile/source context.", false, delegate(JsonElement item)
            {
                string browser = JoinNonBlank(GetString(item, "browser", ""), GetString(item, "profile", ""));
                return new EvidenceItem
                {
                    Section = "Browser",
                    Severity = NormalizeSeverity(GetString(item, "severity", "Info")),
                    Title = FirstNonBlank(GetString(item, "label", ""), "Browser hit"),
                    Source = FirstNonBlank(browser, "Browser"),
                    Detail = GetString(item, "snippet", ""),
                    Extra = JoinNonBlank("Token: " + GetString(item, "token", ""), GetString(item, "historyPath", "")),
                    When = "",
                    Confidence = GetInt(item, "confidence", 0),
                    Score = GetInt(item, "score", 0)
                };
            });
        }



        private void AddDmaPcieSection(JsonElement root)
        {
            AddSection(root, "dmaPcieReviewRecords", "DMA / PCIe", "PCIe, Thunderbolt, USB4, CFexpress, FPGA/DMA-adjacent, and setup-log device context. Review-only unless corroborated by other evidence.", false, delegate(JsonElement item)
            {
                string title = FirstNonBlank(GetString(item, "name", ""), GetString(item, "deviceId", "DMA / PCIe device"));
                string extra = JoinNonBlank(
                    "Manufacturer: " + GetString(item, "manufacturer", ""),
                    "Service: " + GetString(item, "service", ""),
                    "Class: " + GetString(item, "className", ""),
                    "Source: " + GetString(item, "source", ""),
                    "Location: " + GetString(item, "location", ""),
                    "Present: " + GetString(item, "currentlyPresent", ""),
                    "Reason: " + GetString(item, "reviewReason", ""));

                return new EvidenceItem
                {
                    Section = "DMA / PCIe",
                    Severity = NormalizeSeverity(GetString(item, "severity", "Info")),
                    Title = title,
                    Source = FirstNonBlank(GetString(item, "enumerator", ""), "DMA / PCIe review"),
                    Detail = GetString(item, "deviceId", ""),
                    Extra = extra,
                    When = FriendlyWhen(FirstNonBlank(GetString(item, "bestObservedTime", ""), GetString(item, "lastArrivalTime", ""), GetString(item, "installTime", ""))),
                    Confidence = GetInt(item, "confidence", 0),
                    Score = 0
                };
            });
        }

        private void AddExternalDevicesSection(JsonElement root)
        {
            AddSection(root, "externalDevices", "External Devices", "Retained USB connection history for scan context.", false, delegate(JsonElement item)
            {
                bool massStorage = string.Equals(GetString(item, "massStorage", ""), "true", StringComparison.OrdinalIgnoreCase);
                string title = ScannerHelpers.FriendlyWindowsDeviceText(GetString(item, "description", ""), massStorage ? "USB storage device" : "External USB device");
                string detail = ExternalDeviceSummary(item);
                string manufacturer = ScannerHelpers.FriendlyWindowsDeviceText(GetString(item, "manufacturer", ""), "");
                string location = ScannerHelpers.FriendlyWindowsDeviceText(GetString(item, "location", ""), "");
                string extra = JoinNonBlank(
                    "Identifier: " + FriendlyExternalDeviceIdentifier(GetString(item, "deviceId", "")),
                    "Manufacturer: " + manufacturer,
                    "Service: " + GetString(item, "service", ""),
                    "Class: " + GetString(item, "className", ""),
                    "Location: " + location,
                    "Present: " + GetString(item, "currentlyPresent", ""),
                    "Mass storage: " + GetString(item, "massStorage", ""));

                return new EvidenceItem
                {
                    Section = "External Devices",
                    Severity = "Info",
                    Title = title,
                    Source = FirstNonBlank(GetString(item, "enumerator", ""), GetString(item, "source", "USB history")),
                    Detail = detail,
                    Extra = extra,
                    When = FriendlyWhen(FirstNonBlank(GetString(item, "bestObservedTime", ""), GetString(item, "lastArrivalTime", ""))),
                    Confidence = 0,
                    Score = 0
                };
            });
        }

        private static string ExternalDeviceSummary(JsonElement item)
        {
            bool massStorage = string.Equals(GetString(item, "massStorage", ""), "true", StringComparison.OrdinalIgnoreCase);
            bool present = string.Equals(GetString(item, "currentlyPresent", ""), "true", StringComparison.OrdinalIgnoreCase);
            string summary = massStorage ? "Retained USB storage connection record" : "Retained USB device connection record";
            if (present) summary += " currently present";
            return summary;
        }

        private static string FriendlyExternalDeviceIdentifier(string deviceId)
        {
            if (string.IsNullOrWhiteSpace(deviceId)) return "";
            string clean = deviceId.Trim().Replace('/', '\\');
            string[] parts = clean.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2) return parts[0] + "\\" + parts[1];
            return clean;
        }

        private void AddHardwareSection(JsonElement root)
        {
            AddSection(root, "hardwareRecords", "Hardware", "Hardware identity records collected for scan context.", false, delegate(JsonElement item)
            {
                return new EvidenceItem
                {
                    Section = "Hardware",
                    Severity = "Info",
                    Title = FirstNonBlank(GetString(item, "name", ""), "Hardware record"),
                    Source = FirstNonBlank(GetString(item, "category", ""), GetString(item, "source", "Hardware")),
                    Detail = GetString(item, "value", ""),
                    Extra = "Source: " + GetString(item, "source", ""),
                    When = "",
                    Confidence = 0,
                    Score = 0
                };
            });
        }

        private void AddDriversSection(JsonElement root)
        {
            AddSection(root, "drivers", "Drivers", "Loaded drivers, signatures, locations, and suspicious name hits.", false, delegate(JsonElement item)
            {
                bool suspicious = GetBool(item, "suspiciousNamePattern", false);
                bool vulnerable = GetBool(item, "knownVulnerableDriver", false);
                bool windows = GetBool(item, "windowsSystemPath", false);
                bool signed = GetBool(item, "signed", false);
                string severity = vulnerable ? GetString(item, "knownVulnerableDriverSeverity", "Medium") : (suspicious ? "Medium" : (!windows && !signed ? "Low" : "Info"));
                string extra = JoinNonBlank(
                    "Known vulnerable driver: " + vulnerable,
                    "Catalog match: " + GetString(item, "knownVulnerableDriverName", ""),
                    "Match reason: " + GetString(item, "knownVulnerableDriverMatch", ""),
                    "Catalog context: " + GetString(item, "knownVulnerableDriverReason", ""),
                    "Company: " + GetString(item, "company", ""),
                    "Product: " + GetString(item, "productName", ""),
                    "Original file: " + GetString(item, "originalFileName", ""),
                    "SHA-256: " + GetString(item, "sha256", ""),
                    "Signed: " + signed,
                    "Windows path: " + windows,
                    "Suspicious name: " + suspicious);

                return new EvidenceItem
                {
                    Section = "Drivers",
                    Severity = severity,
                    Title = GetString(item, "name", "Driver"),
                    Source = vulnerable ? "Known vulnerable driver catalog" : (signed ? "Signed" : "Unsigned / unknown"),
                    Detail = GetString(item, "path", ""),
                    Extra = extra,
                    When = "",
                    Confidence = vulnerable ? GetInt(item, "knownVulnerableDriverConfidence", 70) : (suspicious ? 50 : 0),
                    Score = 0
                };
            });
        }

        private void AddSection(JsonElement root, string arrayName, string title, string description, bool expanded, Func<JsonElement, EvidenceItem> map)
        {
            JsonElement array;
            var section = new ReportSection(title, description, expanded);

            if (TryGetArray(root, arrayName, out array))
            {
                foreach (var item in array.EnumerateArray())
                {
                    try
                    {
                        EvidenceItem evidence = map(item);
                        if (evidence != null)
                        {
                            section.AllItems.Add(evidence);
                        }
                    }
                    catch
                    {
                    }
                }
            }

            _workspace.Sections.Add(section);
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            SearchPlaceholder.Visibility = string.IsNullOrWhiteSpace(SearchBox.Text)
                ? Visibility.Visible
                : Visibility.Hidden;

            if (ResultsSection.Visibility == Visibility.Visible)
            {
                if (_searchDebounceTimer == null)
                {
                    ApplyFilter();
                    return;
                }

                _searchDebounceTimer.Stop();
                _searchDebounceTimer.Start();
            }
        }

        private void ApplyFilter()
        {
            if (_workspace == null) return;

            string query = SearchBox == null ? string.Empty : (SearchBox.Text ?? string.Empty).Trim();
            foreach (var section in _workspace.Sections)
            {
                IEnumerable<EvidenceItem> rows = string.IsNullOrWhiteSpace(query)
                    ? section.AllItems
                    : section.AllItems.Where(item => item.Contains(query));

                section.SetFilteredRows(rows);
            }
        }

        private void AppendLog(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return;

            LogBox.AppendText("[" + DateTime.Now.ToString("h:mm:ss tt", CultureInfo.CurrentCulture) + "]  " + text + Environment.NewLine);
            LogBox.ScrollToEnd();
        }

        private void GithubButton_Click(object sender, RoutedEventArgs e)
        {
            OpenExternal("https://github.com/GamerIntegrity/gamerintegrity");
        }

        private void BuyMeCoffeeButton_Click(object sender, RoutedEventArgs e)
        {
            OpenExternal("https://buymeacoffee.com/dayzeroac");
        }

        private void ChooseRedactedButton_Click(object sender, RoutedEventArgs e)
        {
            LoadSelectedReport(true);
        }

        private void ChooseNonRedactedButton_Click(object sender, RoutedEventArgs e)
        {
            LoadSelectedReport(false);
        }

        private void ExportRedactedButton_Click(object sender, RoutedEventArgs e)
        {
            ExportReportFiles(true);
        }

        private void ExportNonRedactedButton_Click(object sender, RoutedEventArgs e)
        {
            ExportReportFiles(false);
        }

        private void SectionPreviousPage_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is ReportSection section)
            {
                section.PreviousPage();
            }
        }

        private void SectionNextPage_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is ReportSection section)
            {
                section.NextPage();
            }
        }

        private void LoadSelectedReport(bool redacted)
        {
            if (_lastScanResult == null)
            {
                ShowError("No Scan Loaded", "Run a scan before choosing a view.");
                return;
            }

            string json = redacted ? _lastScanResult.RedactedJsonReportContent : _lastScanResult.JsonReportContent;
            ReportModeText.Text = redacted ? "Redacted view loaded" : "Non-Redacted view loaded";
            LoadReportIntoView(json);
            FadeInResults();
        }

        private void ExportReportFiles(bool redacted)
        {
            if (_lastScanResult == null)
            {
                ShowError("No Scan Loaded", "Run a scan before exporting files.");
                return;
            }

            string html = redacted ? _lastScanResult.RedactedHtmlReportContent : _lastScanResult.HtmlReportContent;
            string json = redacted ? _lastScanResult.RedactedJsonReportContent : _lastScanResult.JsonReportContent;
            if (string.IsNullOrWhiteSpace(html) || string.IsNullOrWhiteSpace(json))
            {
                ShowError("Export Failed", "The selected scan content is not available in memory.");
                return;
            }

            string exportFolder = Path.Combine(AppContext.BaseDirectory, "Reports", DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture) + (redacted ? "_Redacted" : "_NonRedacted"));
            string htmlPath = Path.Combine(exportFolder, redacted ? "GamerIntegrity_Report_Redacted.html" : "GamerIntegrity_Report.html");
            string jsonPath = Path.Combine(exportFolder, redacted ? "GamerIntegrity_Report_Redacted.json" : "GamerIntegrity_Report.json");
            string manifestPath = Path.Combine(exportFolder, redacted ? "GamerIntegrity_Report_Redacted_Integrity.json" : "GamerIntegrity_Report_Integrity.json");

            try
            {
                Directory.CreateDirectory(exportFolder);
                File.WriteAllText(htmlPath, html, new UTF8Encoding(false));
                File.WriteAllText(jsonPath, json, new UTF8Encoding(false));

                ReportIntegrityContext ctx = redacted ? _lastScanResult.RedactedIntegrityContext : _lastScanResult.IntegrityContext;
                bool manifestWritten = ctx != null && ReportWriter.WriteReportIntegrityManifest(ctx, htmlPath, jsonPath, manifestPath, redacted);

                ShowModal("Export Complete",
                    "Report files were created here:\n\n" + exportFolder + (manifestWritten ? "" : "\n\nThe integrity check file could not be written."),
                    !manifestWritten);
            }
            catch (Exception ex)
            {
                ShowError("Export Failed", "The files could not be exported.\n\n" + ex.Message);
            }
        }

        private void OpenExternal(string target)
        {
            try
            {
                Process.Start(new ProcessStartInfo { FileName = target, UseShellExecute = true });
            }
            catch (Exception ex)
            {
                ShowModal("Open Failed",
                    "Windows could not open this target.\n\n" + target + "\n\n" + ex.Message,
                    true);
            }
        }

        private void Nav_Click(object sender, RoutedEventArgs e)
        {
            if (!(sender is Button button)) return;

            SetActiveNav(button);

            if (ReferenceEquals(button, NavResult))
            {
                ArticleScroll.UpdateLayout();
                ArticleScroll.ScrollToTop();
                Dispatcher.BeginInvoke(new Action(() => ArticleScroll.ScrollToTop()), DispatcherPriority.Background);
                return;
            }

            FrameworkElement target = EvidenceSection;
            ScrollToElement(target);
        }

        private void NavSection_Click(object sender, RoutedEventArgs e)
        {
            if (!(sender is Button button)) return;
            if (!(button.CommandParameter is ReportSection section)) return;

            SetActiveNav(button);
            section.IsExpanded = true;
            SectionsItemsControl.UpdateLayout();

            FrameworkElement target = SectionsItemsControl.ItemContainerGenerator.ContainerFromItem(section) as FrameworkElement;
            if (target != null)
            {
                ScrollToElement(target);
                return;
            }

            ScrollToElement(EvidenceSection);
        }

        private void ScrollToElement(FrameworkElement target)
        {
            if (target == null) return;

            target.UpdateLayout();
            target.BringIntoView();
            Dispatcher.BeginInvoke(new Action(() =>
            {
                target.BringIntoView();
            }), DispatcherPriority.Background);
        }

        private void SetActiveNav(Button activeButton)
        {
            ClearNavActiveTags(SidebarPanel, activeButton);
            if (activeButton != null)
            {
                activeButton.Tag = "Active";
            }
        }

        private void ClearNavActiveTags(DependencyObject root, Button activeButton)
        {
            if (root == null) return;

            Button button = root as Button;
            if (button != null && !ReferenceEquals(button, activeButton))
            {
                button.Tag = null;
            }

            int childCount = VisualTreeHelper.GetChildrenCount(root);
            for (int i = 0; i < childCount; i++)
            {
                ClearNavActiveTags(VisualTreeHelper.GetChild(root, i), activeButton);
            }
        }

        private void ShowError(string title, string message)
        {
            ShowModal(title, message, true);
        }

        private void ShowModal(string title, string message, bool isDanger)
        {
            ModalTitleText.Text = title ?? "GamerIntegrity";
            ModalMessageText.Text = message ?? string.Empty;
            ModalOkButton.Style = (Style)FindResource(isDanger ? "Button.Danger" : "Button.Primary");
            ModalOverlay.Visibility = Visibility.Visible;
            ModalOverlay.Opacity = 0;

            var animation = new DoubleAnimation
            {
                From = 0,
                To = 1,
                Duration = TimeSpan.FromMilliseconds(160),
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
            };

            ModalOverlay.BeginAnimation(OpacityProperty, animation);
        }

        private void ModalOkButton_Click(object sender, RoutedEventArgs e)
        {
            HideModal();
        }

        private void HideModal()
        {
            ModalOverlay.Visibility = Visibility.Collapsed;
            ModalOverlay.BeginAnimation(OpacityProperty, null);
            ModalOverlay.Opacity = 1;
        }

        private void ShowAdminGate()
        {
            AdminGatePanel.Visibility = Visibility.Visible;
            AdminGatePanel.Opacity = 1;
            SearchPanel.Visibility = Visibility.Collapsed;
            HideSidebarNow();
        }

        private void RestartAsAdminButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string executablePath = Process.GetCurrentProcess().MainModule.FileName;
                Process.Start(new ProcessStartInfo
                {
                    FileName = executablePath,
                    UseShellExecute = true,
                    Verb = "runas"
                });

                Application.Current.Shutdown();
            }
            catch (Exception ex)
            {
                ShowModal("Admin Restart Failed", "Windows could not restart GamerIntegrity as admin.\n\n" + ex.Message, true);
            }
        }

        private static bool IsRunningAsAdministrator()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        private static string CleanConcernValue(string value)
        {
            string cleaned = string.IsNullOrWhiteSpace(value) ? "n/a" : value.Trim();

            const string suffix = " concern";
            if (cleaned.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                cleaned = cleaned.Substring(0, cleaned.Length - suffix.Length).Trim();
            }

            return string.IsNullOrWhiteSpace(cleaned) ? "n/a" : cleaned;
        }

        private static string FirstNonBlank(params string[] values)
        {
            if (values == null) return string.Empty;

            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }

            return string.Empty;
        }

        private static string NormalizeSeverity(string severity)
        {
            if (string.IsNullOrWhiteSpace(severity)) return "Info";
            string value = severity.Trim();
            if (value.Equals("Critical", StringComparison.OrdinalIgnoreCase)) return "Critical";
            if (value.Equals("High", StringComparison.OrdinalIgnoreCase)) return "High";
            if (value.Equals("Medium", StringComparison.OrdinalIgnoreCase)) return "Medium";
            if (value.Equals("Low", StringComparison.OrdinalIgnoreCase)) return "Low";
            return "Info";
        }

        private static string FriendlyWhen(string when)
        {
            if (string.IsNullOrWhiteSpace(when)) return "Undated";
            string friendly = ScannerHelpers.FriendlyTimestampText(when.Trim());
            return string.IsNullOrWhiteSpace(friendly) ? when.Trim() : friendly;
        }

        private static bool TryGetObject(JsonElement parent, string name, out JsonElement value)
        {
            value = default;

            if (parent.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!parent.TryGetProperty(name, out JsonElement foundValue))
            {
                return false;
            }

            if (foundValue.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            value = foundValue;
            return true;
        }

        private static bool TryGetArray(JsonElement parent, string name, out JsonElement value)
        {
            value = default;

            if (parent.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!parent.TryGetProperty(name, out JsonElement foundValue))
            {
                return false;
            }

            if (foundValue.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            value = foundValue;
            return true;
        }

        private static string GetString(JsonElement parent, string name, string fallback)
        {
            JsonElement value;
            if (parent.ValueKind != JsonValueKind.Object || !parent.TryGetProperty(name, out value))
            {
                return fallback;
            }

            switch (value.ValueKind)
            {
                case JsonValueKind.String:
                    return value.GetString() ?? fallback;
                case JsonValueKind.Number:
                    return value.ToString();
                case JsonValueKind.True:
                    return "true";
                case JsonValueKind.False:
                    return "false";
                case JsonValueKind.Null:
                case JsonValueKind.Undefined:
                    return fallback;
                default:
                    return value.ToString();
            }
        }

        private static int GetInt(JsonElement parent, string name, int fallback)
        {
            JsonElement value;
            if (parent.ValueKind != JsonValueKind.Object || !parent.TryGetProperty(name, out value))
            {
                return fallback;
            }

            if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int number))
            {
                return number;
            }

            int parsed;
            return int.TryParse(GetString(parent, name, ""), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed)
                ? parsed
                : fallback;
        }

        private static bool GetBool(JsonElement parent, string name, bool fallback)
        {
            JsonElement value;
            if (parent.ValueKind != JsonValueKind.Object || !parent.TryGetProperty(name, out value))
            {
                return fallback;
            }

            if (value.ValueKind == JsonValueKind.True) return true;
            if (value.ValueKind == JsonValueKind.False) return false;

            bool parsed;
            return bool.TryParse(GetString(parent, name, ""), out parsed) ? parsed : fallback;
        }

        private static string JoinArray(JsonElement parent, string name)
        {
            JsonElement array;
            if (!TryGetArray(parent, name, out array)) return string.Empty;

            var values = new List<string>();
            foreach (var item in array.EnumerateArray())
            {
                string value = item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString();
                if (!string.IsNullOrWhiteSpace(value)) values.Add(value.Trim());
            }

            return string.Join(", ", values);
        }

        private static string JoinNonBlank(params string[] values)
        {
            var output = new List<string>();
            foreach (string raw in values)
            {
                if (string.IsNullOrWhiteSpace(raw)) continue;
                string value = raw.Trim();
                if (value.EndsWith(":", StringComparison.Ordinal)) continue;
                if (value.EndsWith(": true", StringComparison.OrdinalIgnoreCase) || value.EndsWith(": false", StringComparison.OrdinalIgnoreCase))
                {
                    output.Add(value);
                    continue;
                }
                string[] emptyPrefixes = { "Token: ", "Domain: ", "Type: ", "Time shown from: ", "Determination: ", "Labels: ", "Tokens: ", "Samples: ", "Identifier: ", "Manufacturer: ", "Service: ", "Class: ", "Location: ", "Last write: ", "Source: ", "Company: ", "SHA-256: " };
                bool emptyPrefixed = emptyPrefixes.Any(prefix => value.Equals(prefix.TrimEnd(), StringComparison.OrdinalIgnoreCase));
                if (!emptyPrefixed) output.Add(value);
            }

            return string.Join(" | ", output);
        }
    }

    public sealed class ScanStatusText
    {
        public ScanStatusText(string category, string title, string detail, string tip, string logMessage)
        {
            Category = category;
            Title = title;
            Detail = detail;
            Tip = tip;
            LogMessage = logMessage;
        }

        public string Category { get; }
        public string Title { get; }
        public string Detail { get; }
        public string Tip { get; }
        public string LogMessage { get; }
    }

    public sealed class ReportWorkspaceViewModel : NotifyBase
    {
        public ObservableCollection<MetricItem> Metrics { get; } = new ObservableCollection<MetricItem>();
        public ObservableCollection<ReportSection> Sections { get; } = new ObservableCollection<ReportSection>();

        private string _verdict = "No scan loaded";
        private string _verdictLevel = "";
        private string _verdictBasis = "Run a scan to load results inside this app.";
        private string _overallConcern = "";

        public string Verdict
        {
            get { return _verdict; }
            set { Set(ref _verdict, value); }
        }

        public string VerdictLevel
        {
            get { return _verdictLevel; }
            set { Set(ref _verdictLevel, value); }
        }

        public string VerdictBasis
        {
            get { return _verdictBasis; }
            set { Set(ref _verdictBasis, value); }
        }

        public string OverallConcern
        {
            get { return _overallConcern; }
            set { Set(ref _overallConcern, value); }
        }

        public void Reset()
        {
            Metrics.Clear();
            Sections.Clear();
            Verdict = "No scan loaded";
            VerdictLevel = "";
            VerdictBasis = "Run a scan to load results inside this app.";
            OverallConcern = "";
        }
    }

    public sealed class MetricItem
    {
        public MetricItem(string label, string value, string note)
        {
            Label = label;
            Value = value;
            Note = note;
        }

        public string Label { get; }
        public string Value { get; }
        public string Note { get; }
    }

    public sealed class ReportSection : NotifyBase
    {
        private const int DefaultPageSize = 10;
        private int _currentPage = 1;
        private int _pageSize = DefaultPageSize;

        public ReportSection(string title, string description, bool isExpanded)
        {
            Title = title;
            Description = description;
            IsExpanded = isExpanded;
        }

        private bool _isExpanded;

        public string Title { get; }
        public string Description { get; }

        public bool IsExpanded
        {
            get { return _isExpanded; }
            set { Set(ref _isExpanded, value); }
        }

        public List<EvidenceItem> AllItems { get; } = new List<EvidenceItem>();
        public List<EvidenceItem> FilteredItems { get; } = new List<EvidenceItem>();
        public ObservableCollection<EvidenceItem> PagedItems { get; } = new ObservableCollection<EvidenceItem>();

        public int CurrentPage
        {
            get { return _currentPage; }
            private set { Set(ref _currentPage, value); }
        }

        public int PageSize
        {
            get { return _pageSize; }
            private set { Set(ref _pageSize, Math.Max(1, value)); }
        }

        public int TotalPages
        {
            get
            {
                if (FilteredItems.Count == 0) return 1;
                return (int)Math.Ceiling(FilteredItems.Count / (double)PageSize);
            }
        }

        public bool CanGoPrevious
        {
            get { return CurrentPage > 1; }
        }

        public bool CanGoNext
        {
            get { return CurrentPage < TotalPages; }
        }

        public Visibility PaginationVisibility
        {
            get { return FilteredItems.Count > PageSize ? Visibility.Visible : Visibility.Collapsed; }
        }

        public string CountText
        {
            get
            {
                return FilteredItems.Count.ToString(CultureInfo.InvariantCulture)
                    + " / "
                    + AllItems.Count.ToString(CultureInfo.InvariantCulture);
            }
        }

        public string PageStatusText
        {
            get
            {
                if (FilteredItems.Count == 0) return "0 / 0 Pages";

                return CurrentPage.ToString(CultureInfo.InvariantCulture)
                    + " / "
                    + TotalPages.ToString(CultureInfo.InvariantCulture)
                    + " Pages";
            }
        }

        public void SetFilteredRows(IEnumerable<EvidenceItem> rows)
        {
            FilteredItems.Clear();
            if (rows != null) FilteredItems.AddRange(rows);

            CurrentPage = 1;
            RefreshPage();
        }

        public void PreviousPage()
        {
            if (!CanGoPrevious) return;
            CurrentPage--;
            RefreshPage();
        }

        public void NextPage()
        {
            if (!CanGoNext) return;
            CurrentPage++;
            RefreshPage();
        }

        private void RefreshPage()
        {
            int totalPages = TotalPages;
            if (CurrentPage > totalPages) CurrentPage = totalPages;
            if (CurrentPage < 1) CurrentPage = 1;

            PagedItems.Clear();

            foreach (var item in FilteredItems.Skip((CurrentPage - 1) * PageSize).Take(PageSize))
            {
                PagedItems.Add(item);
            }

            OnPropertyChanged(nameof(TotalPages));
            OnPropertyChanged(nameof(CanGoPrevious));
            OnPropertyChanged(nameof(CanGoNext));
            OnPropertyChanged(nameof(PaginationVisibility));
            OnPropertyChanged(nameof(CountText));
            OnPropertyChanged(nameof(PageStatusText));
        }
    }

    public sealed class EvidenceItem
    {
        private string _searchText;

        public string Section { get; set; } = "";
        public string Severity { get; set; } = "Info";
        public string Title { get; set; } = "";
        public string Source { get; set; } = "";
        public string Detail { get; set; } = "";
        public string Extra { get; set; } = "";
        public string When { get; set; } = "";
        public int Confidence { get; set; }
        public int Score { get; set; }

        public string ConfidenceText
        {
            get { return Confidence > 0 ? Confidence.ToString(CultureInfo.InvariantCulture) + "% confidence" : "Context"; }
        }

        public string ScoreText
        {
            get { return Score > 0 ? Score.ToString(CultureInfo.InvariantCulture) + " pts" : ""; }
        }

        public bool Contains(string query)
        {
            if (string.IsNullOrWhiteSpace(query)) return true;
            if (_searchText == null)
            {
                _searchText = string.Join("\n", new[] { Section, Severity, Title, Source, Detail, Extra, When, ConfidenceText, ScoreText });
            }

            return _searchText.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }

    public abstract class NotifyBase : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        protected void Set<T>(ref T field, T value, string propertyName = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) return;
            field = value;
            OnPropertyChanged(propertyName ?? GetCallerName());
        }

        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChangedEventHandler handler = PropertyChanged;
            if (handler != null) handler(this, new PropertyChangedEventArgs(propertyName));
        }

        private static string GetCallerName()
        {
            var trace = new StackTrace();
            var frame = trace.GetFrame(2);
            var method = frame == null ? null : frame.GetMethod();
            return method == null ? string.Empty : method.Name.Replace("set_", string.Empty);
        }
    }
}
