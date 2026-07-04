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

        public MainWindow()
        {
            InitializeComponent();
            DataContext = _workspace;
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
            ScanProgressBar.Value = 0;
            ProgressPercentText.Text = "0%";
            ProgressStageText.Text = "Getting scan ready...";

            _workspace.Reset();
            ArticleScroll.ScrollToTop();
            Dispatcher.BeginInvoke(new Action(UpdateScanLayoutHeight), DispatcherPriority.Background);
        }

        private void UpdateProgress(int percent, string stage)
        {
            int safePercent = Math.Max(0, Math.Min(100, percent));
            ScanProgressBar.Value = safePercent;
            ProgressPercentText.Text = safePercent.ToString(CultureInfo.InvariantCulture) + "%";

            if (!string.IsNullOrWhiteSpace(stage))
            {
                ProgressStageText.Text = stage;
                AppendLog(stage);
            }
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
                ScanProgressBar.Value = 100;
                ProgressPercentText.Text = "100%";
                ProgressStageText.Text = "Scan complete. Choose Redacted or Non-Redacted to view results.";
                ReportChoicePanel.Visibility = Visibility.Visible;
                ActivitySection.Visibility = Visibility.Collapsed;
                AppendLog("Scan complete. Waiting for Redacted or Non-Redacted view choice.");
                return;
            }

            ProgressStageText.Text = result.ExitCode == 2
                ? "Scan finished, but results could not be prepared."
                : "Scan failed.";

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
                // Keep the search box usable even if layout measurements are not ready yet.
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

            // The scan page lives inside the article padding. Keep it responsive while letting the log fill the open space.
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
                        _workspace.Metrics.Add(new MetricItem("Launch", GetString(summary, "executionArtifacts", "0"), "AmCache / Prefetch"));
                        _workspace.Metrics.Add(new MetricItem("Downloads", GetString(summary, "browserSourceDownloadMatches", "0"), "History and download hits"));
                        _workspace.Metrics.Add(new MetricItem("Projects", GetString(summary, "sourceProjectGroups", "0"), "Grouped build/source hits"));
                    }
                    else
                    {
                        _workspace.Verdict = "Scan report loaded";
                        _workspace.VerdictBasis = "Summary data was not present, but scan rows were loaded.";
                    }

                    AddTimelineSection(root);
                    AddFindingsSection(root);
                    AddSourceProjectSection(root);
                    AddExecutionSection(root);
                    AddBrowserDownloadSection(root);
                    AddRuntimeSection(root);
                    AddInstalledProgramsSection(root);
                    AddBrowserKeywordsSection(root);
                    AddFileNameSection(root);
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
                string extra = JoinNonBlank("Time basis: " + GetString(item, "timeType", ""), summary);

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

        private void AddExternalDevicesSection(JsonElement root)
        {
            AddSection(root, "externalDevices", "External Devices", "USB and external device history for scan context.", false, delegate(JsonElement item)
            {
                string title = FirstNonBlank(GetString(item, "description", ""), GetString(item, "deviceId", "External device"));
                string extra = JoinNonBlank(
                    "Manufacturer: " + GetString(item, "manufacturer", ""),
                    "Service: " + GetString(item, "service", ""),
                    "Class: " + GetString(item, "className", ""),
                    "Location: " + GetString(item, "location", ""),
                    "Present: " + GetString(item, "currentlyPresent", ""),
                    "Mass storage: " + GetString(item, "massStorage", ""));

                return new EvidenceItem
                {
                    Section = "External Devices",
                    Severity = "Info",
                    Title = title,
                    Source = FirstNonBlank(GetString(item, "enumerator", ""), GetString(item, "source", "USB history")),
                    Detail = GetString(item, "deviceId", ""),
                    Extra = extra,
                    When = FriendlyWhen(FirstNonBlank(GetString(item, "bestObservedTime", ""), GetString(item, "lastArrivalTime", ""))),
                    Confidence = 0,
                    Score = 0
                };
            });
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
                bool windows = GetBool(item, "windowsSystemPath", false);
                bool signed = GetBool(item, "signed", false);
                string severity = suspicious ? "Medium" : (!windows && !signed ? "Low" : "Info");
                string extra = JoinNonBlank(
                    "Company: " + GetString(item, "company", ""),
                    "SHA-256: " + GetString(item, "sha256", ""),
                    "Signed: " + signed,
                    "Windows path: " + windows,
                    "Suspicious name: " + suspicious);

                return new EvidenceItem
                {
                    Section = "Drivers",
                    Severity = severity,
                    Title = GetString(item, "name", "Driver"),
                    Source = signed ? "Signed" : "Unsigned / unknown",
                    Detail = GetString(item, "path", ""),
                    Extra = extra,
                    When = "",
                    Confidence = suspicious ? 50 : 0,
                    Score = 0
                };
            });
        }

        private void AddSection(JsonElement root, string arrayName, string title, string description, bool expanded, Func<JsonElement, EvidenceItem> map)
        {
            JsonElement array;
            var section = new ReportSection(title, description, false);

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
                        // Skip malformed individual rows but keep the rest of the report usable.
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
                ApplyFilter();
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

        private static string FirstNonBlank(string value, string fallback)
        {
            return string.IsNullOrWhiteSpace(value) ? fallback : value;
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
            return when.Trim();
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
                string[] emptyPrefixes = { "Token: ", "Domain: ", "Type: ", "Time basis: ", "Determination: ", "Labels: ", "Tokens: ", "Samples: ", "Manufacturer: ", "Service: ", "Class: ", "Location: ", "Last write: ", "Source: ", "Company: ", "SHA-256: " };
                bool emptyPrefixed = emptyPrefixes.Any(prefix => value.Equals(prefix.TrimEnd(), StringComparison.OrdinalIgnoreCase));
                if (!emptyPrefixed) output.Add(value);
            }

            return string.Join(" | ", output);
        }
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
        public ObservableCollection<EvidenceItem> FilteredItems { get; } = new ObservableCollection<EvidenceItem>();
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

            foreach (var row in rows)
            {
                FilteredItems.Add(row);
            }

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
            string text = string.Join("\n", new[] { Section, Severity, Title, Source, Detail, Extra, When, ConfidenceText, ScoreText });
            return text.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0;
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
