using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace GamerIntegrity
{
    internal static class BrowserScanner
    {
        private const int MaxHistoryRowsPerSource = 100000;
        private const int MaxDownloadRowsPerSource = 25000;
        private const int MaxMatchesPerSource = 200;

        private static readonly string[] DirectBrowserCheatTerms =
        {
            "cheat", "cheats", "hack", "hacks", "aimbot", "aim bot", "triggerbot", "trigger bot", "wallhack", "wall hack",
            "esp", "player esp", "loot esp", "radar hack", "chams", "spinbot", "ragebot", "legitbot", "silent aim",
            "bhop", "bunnyhop", "bunny hop", "rcs", "no recoil", "norecoil", "skin changer", "skinchanger",
            "injector", "dll injector", "extreme injector", "mapper", "manual map", "manual mapper", "kdmapper", "kd mapper",
            "driver mapper", "kernel mapper", "spoofer", "hwid spoofer", "unban", "cheat engine", "cheatengine"
        };

        private static readonly string[] ExplicitCheatContextTerms =
        {
            "cs2 cheat", "cs2 esp", "cs2 external", "cs2 internal", "counter-strike 2 cheat", "roblox cheat", "valorant cheat",
            "trace cleaner", "vanguard bypass", "eac bypass", "battleye bypass", "faceit bypass", "ricochet bypass", "anti-cheat bypass", "anticheat bypass", "download cheats",
            "hacks cheats", "cheats & hacks", "cheats and hacks", "game hacking and cheats", "cheat source",
            "hack source", "cheat src", "cheat loader", "cheat provider", "cheat shop", "cheat store", "cheat marketplace"
        };

        private static readonly string[] StrongBrowserContextTerms =
        {
            "cheat site", "cheat domain", "cheat provider", "cheat shop", "cheat store", "cheat marketplace",
            "download/local path", "downloads.php", "download.php", "download/file", "file=", "id="
        };

        private static readonly string[] LegitReviewContextTerms =
        {
            "gamerintegrity", "gamer integrity report", "gamer integrity documentation", "dayzeroanticheat", "dayzero-anticheat",
            "anticheat", "anti-cheat", "anti cheat", "cheat detection", "catch cheats", "pc checker for gamers",
            "integrity scanner", "integrity report", "fair play", "review evidence"
        };

        private static readonly string[] LegitReviewOverrideTerms =
        {
            "spoofer", "injector", "mapper", "kdmapper", "aimbot", "triggerbot", "wallhack", "esp",
            "ragebot", "spinbot", "cheat provider", "cheat shop", "cheat store"
        };

        private static readonly string[] CheatDomainTerms =
        {
            "cheat", "gamehack", "gamehacks", "cheathack", "hackcheat", "aimbot", "wallhack", "triggerbot",
            "ragebot", "spinbot", "spoofer", "kdmapper", "injector", "bypass", "unban", "colorbot", "pixelbot", "executor"
        };

        private static readonly string[] ReviewDomainContextTerms =
        {
            "anticheat", "cheatdetection", "gamerintegrity", "integrityscanner"
        };

        private static readonly string[] WeakBrowserTokens =
        {
            "source", "src", "project", "provider", "dayzero", "slapp", "antic", "auth", "menu", "panel",
            "external", "internal", "driver", "sdk", "dump", "dumper", "loader", "loader src", "loader source",
            "loader project", "source code", "source sdk", "game sdk", "offsets", "client", "client dll",
            "private", "invite", "trace", "traces", "paste", "crack", "leak", "leaked", "slapping"
        };

        private static readonly string[] DownloadUrlTerms =
        {
            "/download", "downloads.php", "?do=file", "&do=file", "/file/", ".zip", ".rar", ".7z", ".exe", ".dll", ".sys"
        };

        public static BrowserScanResult Scan(ScanReport report)
        {
            var result = new BrowserScanResult();
            var sources = DiscoverBrowserHistorySources();
            result.Sources.AddRange(sources);

            foreach (var source in sources)
            {
                ScanSource(report, source, result);
            }

            DeduplicateBrowserMatches(result.HistoryMatches);
            DeduplicateBrowserDownloads(result.DownloadMatches);
            ScannerHelpers.SortEvidence(result.HistoryMatches, m => m.Score, m => m.Confidence, m => m.Severity);
            ScannerHelpers.SortEvidence(result.DownloadMatches, m => m.Score, m => m.Confidence, m => m.Severity);

            AddBrowserFindings(report, result);
            return result;
        }

        private static void ScanSource(ScanReport report, BrowserHistorySource source, BrowserScanResult result)
        {
            string copyPath = "";
            try
            {
                copyPath = CopyDatabaseForRead(source, report);
                if (string.IsNullOrWhiteSpace(copyPath)) return;

                var builder = new SqliteConnectionStringBuilder
                {
                    DataSource = copyPath,
                    Mode = SqliteOpenMode.ReadOnly
                };

                using (var connection = new SqliteConnection(builder.ToString()))
                {
                    connection.Open();
                    if (IsFirefoxSource(source))
                    {
                        ScanFirefoxHistory(connection, source, result.HistoryMatches, report);
                        ScanFirefoxDownloads(connection, source, result.DownloadMatches, report);
                    }
                    else
                    {
                        ScanChromiumHistory(connection, source, result.HistoryMatches, report);
                        ScanChromiumDownloads(connection, source, result.DownloadMatches, report);
                    }
                }
            }
            catch (Exception ex)
            {
                report.AddLimitation("Browser", source.Browser + " " + source.Profile, source.HistoryPath, "Could not parse browser SQLite database: " + CleanExceptionMessage(ex), Severity.Low);
            }
            finally
            {
                TryDelete(copyPath);
            }
        }

        private static string CopyDatabaseForRead(BrowserHistorySource source, ScanReport report)
        {
            if (source == null || string.IsNullOrWhiteSpace(source.HistoryPath)) return "";
            try
            {
                if (!File.Exists(source.HistoryPath))
                {
                    report.AddLimitation("Browser", source.Browser + " " + source.Profile, source.HistoryPath, "History database no longer exists at scan time.", Severity.Info);
                    return "";
                }

                string tempRoot = Path.Combine(Path.GetTempPath(), "GamerIntegrity", "BrowserCopies");
                Directory.CreateDirectory(tempRoot);
                string ext = Path.GetExtension(source.HistoryPath);
                string copy = Path.Combine(tempRoot, Guid.NewGuid().ToString("N") + (string.IsNullOrWhiteSpace(ext) ? ".sqlite" : ext));

                using (var input = new FileStream(source.HistoryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var output = new FileStream(copy, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    input.CopyTo(output);
                }

                CopySidecarIfPresent(source.HistoryPath, copy, "-wal");
                CopySidecarIfPresent(source.HistoryPath, copy, "-shm");
                return copy;
            }
            catch (Exception ex)
            {
                report.AddLimitation("Browser", source.Browser + " " + source.Profile, source.HistoryPath, "Could not copy locked browser history database: " + CleanExceptionMessage(ex), Severity.Low);
                return "";
            }
        }

        private static void CopySidecarIfPresent(string sourceDatabasePath, string copyDatabasePath, string suffix)
        {
            try
            {
                string source = sourceDatabasePath + suffix;
                if (File.Exists(source)) File.Copy(source, copyDatabasePath + suffix, true);
            }
            catch { }
        }

        private static void ScanChromiumHistory(SqliteConnection connection, BrowserHistorySource source, List<BrowserHistoryMatch> matches, ScanReport report)
        {
            if (!TableExists(connection, "urls"))
            {
                report.AddLimitation("Browser", source.Browser + " " + source.Profile, source.HistoryPath, "Chromium urls table was not found in the history database.", Severity.Info);
                return;
            }

            string timeColumn = ColumnExists(connection, "urls", "last_visit_time") ? "last_visit_time" : "0";
            string titleColumn = ColumnExists(connection, "urls", "title") ? "title" : "''";
            string sql = "SELECT url, " + titleColumn + " AS title, " + timeColumn + " AS whenValue FROM urls WHERE url IS NOT NULL ORDER BY whenValue DESC LIMIT @limit";
            var rules = Rules.BrowserHistoryRules();
            foreach (var row in ReadRows(connection, sql, MaxHistoryRowsPerSource, report, source, "Chromium history rows"))
            {
                AddHistoryRuleMatches(source, row.Url, row.Title, row.When, "Browser visit time", rules, matches);
                if (matches.Count(m => SameSource(m, source)) >= MaxMatchesPerSource) break;
            }
        }

        private static void ScanFirefoxHistory(SqliteConnection connection, BrowserHistorySource source, List<BrowserHistoryMatch> matches, ScanReport report)
        {
            if (!TableExists(connection, "moz_places"))
            {
                report.AddLimitation("Browser", source.Browser + " " + source.Profile, source.HistoryPath, "Firefox moz_places table was not found in the history database.", Severity.Info);
                return;
            }

            string timeColumn = ColumnExists(connection, "moz_places", "last_visit_date") ? "last_visit_date" : "0";
            string titleColumn = ColumnExists(connection, "moz_places", "title") ? "title" : "''";
            string sql = "SELECT url, " + titleColumn + " AS title, " + timeColumn + " AS whenValue FROM moz_places WHERE url IS NOT NULL ORDER BY whenValue DESC LIMIT @limit";
            var rules = Rules.BrowserHistoryRules();
            foreach (var row in ReadRows(connection, sql, MaxHistoryRowsPerSource, report, source, "Firefox history rows"))
            {
                AddHistoryRuleMatches(source, row.Url, row.Title, row.When, "Browser visit time", rules, matches);
                if (matches.Count(m => SameSource(m, source)) >= MaxMatchesPerSource) break;
            }
        }

        private static void ScanChromiumDownloads(SqliteConnection connection, BrowserHistorySource source, List<BrowserDownloadMatch> matches, ScanReport report)
        {
            if (!TableExists(connection, "downloads")) return;

            var columns = GetColumns(connection, "downloads");
            string idExpr = columns.Contains("id") ? "id" : "0";
            string currentPathExpr = FirstColumnExpression(columns, "current_path", "target_path", "full_path");
            string targetPathExpr = FirstColumnExpression(columns, "target_path", "current_path", "full_path");
            string tabUrlExpr = FirstColumnExpression(columns, "tab_url", "site_url", "referrer", "original_url");
            string siteUrlExpr = FirstColumnExpression(columns, "site_url", "tab_url", "referrer", "original_url");
            string startTimeExpr = FirstColumnExpression(columns, "start_time", "end_time", "last_access_time");
            string sql = "SELECT " + idExpr + " AS download_id, " + currentPathExpr + " AS current_path, " + targetPathExpr + " AS target_path, " + tabUrlExpr + " AS tab_url, " + siteUrlExpr + " AS site_url, " + startTimeExpr + " AS whenValue FROM downloads LIMIT @limit";
            var chainUrls = ReadChromiumDownloadUrlChains(connection);
            var rules = Rules.BrowserDownloadRules();

            foreach (var row in ReadRows(connection, sql, MaxDownloadRowsPerSource, report, source, "Chromium download rows"))
            {
                string local = FirstNonBlank(row.CurrentPath, row.TargetPath);
                string chain = GetDownloadChain(chainUrls, row.DownloadId);
                bool actualDownloadRecord = !string.IsNullOrWhiteSpace(local) || !string.IsNullOrWhiteSpace(chain) || LooksLikeDownloadUrl(row.Url) || LooksLikeDownloadUrl(row.SecondaryUrl);
                if (!actualDownloadRecord) continue;
                string url = FirstNonBlank(chain, row.Url, row.SecondaryUrl);
                string snippet = ScannerHelpers.CollapseWhitespaceForDisplay(JoinNonBlank(url, row.SecondaryUrl, local));
                AddDownloadRuleMatches(source, url, local, snippet, row.When, "Browser download time", rules, matches, true);
                if (matches.Count(m => SameSource(m, source)) >= MaxMatchesPerSource) break;
            }
        }

        private static void ScanFirefoxDownloads(SqliteConnection connection, BrowserHistorySource source, List<BrowserDownloadMatch> matches, ScanReport report)
        {
            if (!TableExists(connection, "moz_places")) return;

            var historyColumns = GetColumns(connection, "moz_places");
            string titleColumn = historyColumns.Contains("title") ? "title" : "''";
            string timeColumn = historyColumns.Contains("last_visit_date") ? "last_visit_date" : "0";

            string sql = "SELECT url, " + titleColumn + " AS title, " + timeColumn + " AS whenValue FROM moz_places WHERE url IS NOT NULL ORDER BY whenValue DESC LIMIT @limit";
            var rules = Rules.BrowserDownloadRules();
            foreach (var row in ReadRows(connection, sql, MaxDownloadRowsPerSource, report, source, "Firefox download/source rows"))
            {
                string snippet = ScannerHelpers.CollapseWhitespaceForDisplay(JoinNonBlank(row.Url, row.Title));
                if (LooksLikeDownloadUrl(row.Url)) AddDownloadRuleMatches(source, row.Url, "", snippet, row.When, "Browser visit time", rules, matches, true);
                if (matches.Count(m => SameSource(m, source)) >= MaxMatchesPerSource) break;
            }

            if (!TableExists(connection, "moz_annos") || !TableExists(connection, "moz_anno_attributes")) return;

            string annoSql = "SELECT p.url, p.title, p.last_visit_date AS whenValue, a.content AS local_path, aa.name AS anno_name FROM moz_places p JOIN moz_annos a ON a.place_id = p.id JOIN moz_anno_attributes aa ON aa.id = a.anno_attribute_id WHERE aa.name LIKE 'downloads/%' LIMIT @limit";
            foreach (var row in ReadRows(connection, annoSql, MaxDownloadRowsPerSource, report, source, "Firefox download annotation rows"))
            {
                string local = NormalizeFirefoxLocalPath(row.CurrentPath);
                string snippet = ScannerHelpers.CollapseWhitespaceForDisplay(JoinNonBlank(row.Url, row.Title, local));
                if (!string.IsNullOrWhiteSpace(local) || LooksLikeDownloadUrl(row.Url)) AddDownloadRuleMatches(source, row.Url, local, snippet, row.When, "Browser download record", rules, matches, true);
                if (matches.Count(m => SameSource(m, source)) >= MaxMatchesPerSource) break;
            }
        }

        private static IEnumerable<BrowserSqlRow> ReadRows(SqliteConnection connection, string sql, int limit, ScanReport report, BrowserHistorySource source, string scope)
        {
            var rows = new List<BrowserSqlRow>();
            try
            {
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = sql;
                    command.Parameters.AddWithValue("@limit", Math.Max(1, limit));
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            var row = new BrowserSqlRow
                            {
                                DownloadId = GetInt64(reader, "download_id"),
                                Url = GetString(reader, "url"),
                                SecondaryUrl = FirstNonBlank(GetString(reader, "site_url"), GetString(reader, "tab_url")),
                                Title = GetString(reader, "title"),
                                CurrentPath = FirstNonBlank(GetString(reader, "current_path"), GetString(reader, "local_path")),
                                TargetPath = GetString(reader, "target_path"),
                                When = ConvertBrowserTime(GetInt64(reader, "whenValue"), source == null ? "" : source.StoreType)
                            };
                            rows.Add(row);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                report.AddLimitation("Browser", (source == null ? "Browser" : source.Browser + " " + source.Profile), source == null ? "" : source.HistoryPath, scope + " could not be read: " + CleanExceptionMessage(ex), Severity.Low);
            }
            return rows;
        }

        private static void AddHistoryRuleMatches(BrowserHistorySource source, string url, string title, string when, string timeType, List<FileNameRule> rules, List<BrowserHistoryMatch> matches)
        {
            string haystack = ScannerHelpers.CollapseWhitespaceForDisplay(JoinNonBlank(url, title));
            if (string.IsNullOrWhiteSpace(haystack) || IsSelfNoiseBrowserEvidence(haystack) || IsKnownBenignBrowserEvidence(haystack)) return;
            var domainRule = BuildBrowserDomainRule(url, false);
            if (domainRule != null)
            {
                matches.Add(new BrowserHistoryMatch
                {
                    Browser = source.Browser,
                    Profile = source.Profile,
                    HistoryPath = source.HistoryPath,
                    Token = domainRule.Token,
                    Label = domainRule.Label,
                    Snippet = BuildDisplaySnippet(url, title, when, timeType),
                    When = when,
                    TimeType = timeType,
                    Severity = domainRule.Severity,
                    Confidence = domainRule.Confidence,
                    Score = domainRule.Score
                });
            }
            foreach (var rule in rules)
            {
                foreach (string variant in BrowserSearchVariants(rule.Token))
                {
                    if (!BrowserTokenMatches(haystack, variant)) continue;
                    FileNameRule adjustedRule = ScannerService.AdjustRuleForEvidenceContext(rule, haystack, "BrowserHistory");
                    if (adjustedRule == null) break;
                    adjustedRule = TuneBrowserRule(adjustedRule, haystack, false, false);
                    matches.Add(new BrowserHistoryMatch
                    {
                        Browser = source.Browser,
                        Profile = source.Profile,
                        HistoryPath = source.HistoryPath,
                        Token = adjustedRule.Token,
                        Label = adjustedRule.Label,
                        Snippet = BuildDisplaySnippet(url, title, when, timeType),
                        When = when,
                        TimeType = timeType,
                        Severity = adjustedRule.Severity,
                        Confidence = adjustedRule.Confidence,
                        Score = adjustedRule.Score
                    });
                    break;
                }
            }
        }

        private static void AddDownloadRuleMatches(BrowserHistorySource source, string url, string localPath, string snippet, string when, string timeType, List<FileNameRule> rules, List<BrowserDownloadMatch> matches, bool actualDownloadRecord)
        {
            string haystack = ScannerHelpers.CollapseWhitespaceForDisplay(JoinNonBlank(url, localPath, snippet));
            if (string.IsNullOrWhiteSpace(haystack) || IsSelfNoiseBrowserEvidence(haystack) || IsKnownBenignBrowserEvidence(haystack)) return;
            bool hasLocalPath = !string.IsNullOrWhiteSpace(localPath);
            actualDownloadRecord = actualDownloadRecord || hasLocalPath || LooksLikeDownloadUrl(url);
            if (!actualDownloadRecord) return;
            var domainRule = BuildBrowserDomainRule(url, true);
            if (domainRule != null)
            {
                var domainMatch = new BrowserDownloadMatch
                {
                    Browser = source.Browser,
                    Profile = source.Profile,
                    HistoryPath = source.HistoryPath,
                    Token = domainRule.Token,
                    Label = domainRule.Label,
                    Url = CleanUrlCandidate(url),
                    Domain = DomainFromUrl(url),
                    LocalPath = localPath ?? "",
                    EvidenceType = hasLocalPath ? "download/local path" : (actualDownloadRecord ? "download record" : "source/history URL"),
                    Snippet = BuildDisplaySnippet(url, localPath, when, timeType, snippet),
                    When = when,
                    TimeType = timeType,
                    Severity = domainRule.Severity,
                    Confidence = domainRule.Confidence,
                    Score = domainRule.Score
                };
                if (!IsKnownBenignBrowserDownloadMatch(domainMatch)) matches.Add(domainMatch);
            }
            foreach (var rule in rules)
            {
                if (!BrowserTokenMatches(haystack, rule.Token)) continue;
                string evidenceKind = hasLocalPath ? "BrowserDownloadLocal" : (actualDownloadRecord ? "BrowserDownloadRecord" : "BrowserSource");
                FileNameRule adjustedRule = ScannerService.AdjustRuleForEvidenceContext(rule, haystack, evidenceKind);
                if (adjustedRule == null) continue;
                adjustedRule = TuneBrowserRule(adjustedRule, haystack, hasLocalPath, actualDownloadRecord);
                var match = new BrowserDownloadMatch
                {
                    Browser = source.Browser,
                    Profile = source.Profile,
                    HistoryPath = source.HistoryPath,
                    Token = adjustedRule.Token,
                    Label = adjustedRule.Label,
                    Url = CleanUrlCandidate(url),
                    Domain = DomainFromUrl(url),
                    LocalPath = localPath ?? "",
                    EvidenceType = hasLocalPath ? "download/local path" : (actualDownloadRecord ? "download record" : "source/history URL"),
                    Snippet = BuildDisplaySnippet(url, localPath, when, timeType, snippet),
                    When = when,
                    TimeType = timeType,
                    Severity = adjustedRule.Severity,
                    Confidence = adjustedRule.Confidence,
                    Score = adjustedRule.Score
                };
                if (!IsKnownBenignBrowserDownloadMatch(match)) matches.Add(match);
            }
        }

        private static void AddBrowserFindings(ScanReport report, BrowserScanResult result)
        {
            if (result.HistoryMatches.Count > 0)
            {
                var sample = string.Join("\n", result.HistoryMatches.Take(12).Select(m => "- " + m.Browser + " " + m.Profile + ": " + m.Token + " [" + m.Label + "]"));
                report.AddFinding("Browser History", "Browser/domain keyword detections found", sample, result.HistoryMatches.Max(m => m.Severity), Math.Min(95, result.HistoryMatches.Max(m => m.Confidence)), Math.Min(160, result.HistoryMatches.Sum(m => m.Score)));
            }
            else report.AddFinding("Browser History", "No browser/domain keyword detections found", "Detected browser profiles were scanned with direct SQLite parsing. Profiles found: " + result.Sources.Count + ".", Severity.Info, 60, 0);

            if (result.DownloadMatches.Count > 0)
            {
                var sample = BuildBrowserDownloadFindingSample(result.DownloadMatches, 12);
                report.AddFinding("Browser Source/Download Evidence", "Browser source/download evidence found", sample, result.DownloadMatches.Max(m => m.Severity), Math.Min(95, result.DownloadMatches.Max(m => m.Confidence)), Math.Min(160, result.DownloadMatches.Sum(m => m.Score)));
            }
            else report.AddFinding("Browser Source/Download Evidence", "No browser source/download evidence found", "Browser history/download databases were checked with direct SQLite parsing for URL, source, and local download records.", Severity.Info, 60, 0);
        }

        private static string BuildBrowserDownloadFindingSample(List<BrowserDownloadMatch> matches, int limit)
        {
            var rows = matches
                .GroupBy(m => BrowserDownloadDisplayKey(m), StringComparer.OrdinalIgnoreCase)
                .Select(g => BuildBrowserDownloadFindingSampleRow(g.ToList()))
                .Where(row => !string.IsNullOrWhiteSpace(row))
                .Take(limit);

            return string.Join("\n", rows);
        }

        private static string BrowserDownloadDisplayKey(BrowserDownloadMatch match)
        {
            string urlKey = NormalizeBrowserDownloadUrlForMerge(match.Url);
            if (!string.IsNullOrWhiteSpace(urlKey)) return JoinNonBlank(match.Browser, match.Profile, urlKey);

            string localKey = NormalizeBrowserLocalPathForMerge(match.LocalPath);
            if (!string.IsNullOrWhiteSpace(localKey)) return JoinNonBlank(match.Browser, match.Profile, localKey);

            return JoinNonBlank(match.Browser, match.Profile, ExtractBrowserItemKey(match.Snippet));
        }

        private static string BuildBrowserDownloadFindingSampleRow(List<BrowserDownloadMatch> items)
        {
            if (items == null || items.Count == 0) return "";

            var best = items
                .OrderByDescending(m => m.Severity)
                .ThenByDescending(m => m.Confidence)
                .ThenByDescending(m => m.Score)
                .ThenByDescending(m => SafeParseWhen(m.When))
                .First();

            string target = string.IsNullOrWhiteSpace(best.Url) ? best.LocalPath : best.Url;
            string tokenText = JoinLimited(items.SelectMany(m => SplitTokenText(m.Token)), 6);
            string suffix = items.Count > 1 ? " (" + items.Count.ToString(CultureInfo.InvariantCulture) + " related record(s) collapsed)" : "";

            return "- " + best.Browser + " " + best.Profile + ": " + tokenText + " | " + target + suffix;
        }

        private static IEnumerable<string> SplitTokenText(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) yield break;
            foreach (string part in value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string item = part.Trim();
                if (!string.IsNullOrWhiteSpace(item)) yield return item;
            }
        }

        private static DateTime SafeParseWhen(string value)
        {
            DateTime dt;
            if (DateTime.TryParse(value, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out dt)) return dt;
            if (DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out dt)) return dt;
            return DateTime.MinValue;
        }

        private static Dictionary<long, string> ReadChromiumDownloadUrlChains(SqliteConnection connection)
        {
            var map = new Dictionary<long, string>();
            if (!TableExists(connection, "downloads_url_chains")) return map;
            try
            {
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT download_id, url FROM downloads_url_chains ORDER BY download_id, chain_index";
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            long id = GetInt64(reader, "download_id");
                            string url = GetString(reader, "url");
                            if (id <= 0 || string.IsNullOrWhiteSpace(url)) continue;
                            string current;
                            if (map.TryGetValue(id, out current)) map[id] = current + " " + url;
                            else map[id] = url;
                        }
                    }
                }
            }
            catch { }
            return map;
        }

        private static bool TableExists(SqliteConnection connection, string table)
        {
            try
            {
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=@name LIMIT 1";
                    command.Parameters.AddWithValue("@name", table);
                    object value = command.ExecuteScalar();
                    return value != null && value != DBNull.Value;
                }
            }
            catch { return false; }
        }

        private static bool ColumnExists(SqliteConnection connection, string table, string column)
        {
            return GetColumns(connection, table).Contains(column);
        }

        private static HashSet<string> GetColumns(SqliteConnection connection, string table)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "PRAGMA table_info(" + table.Replace("]", "") + ")";
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read()) set.Add(GetString(reader, "name"));
                    }
                }
            }
            catch { }
            return set;
        }

        private static string FirstColumnExpression(HashSet<string> columns, params string[] names)
        {
            foreach (string name in names)
            {
                if (columns.Contains(name)) return name;
            }
            return "''";
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
            if (string.IsNullOrWhiteSpace(baseDir) || !Directory.Exists(baseDir)) return;
            foreach (string profile in SafeEnumerateDirectories(baseDir).Take(100))
            {
                string history = Path.Combine(profile, "History");
                if (!File.Exists(history)) continue;
                string name = Path.GetFileName(profile);
                if (string.IsNullOrWhiteSpace(name)) name = browser;
                sources.Add(new BrowserHistorySource { Browser = browser, Profile = name, HistoryPath = history, StoreType = "Chromium" });
            }
            string direct = Path.Combine(baseDir, "History");
            if (File.Exists(direct) && !sources.Any(s => s.HistoryPath.Equals(direct, StringComparison.OrdinalIgnoreCase)))
                sources.Add(new BrowserHistorySource { Browser = browser, Profile = Path.GetFileName(baseDir), HistoryPath = direct, StoreType = "Chromium" });
        }

        private static void AddFirefoxHistorySources(List<BrowserHistorySource> sources, string baseDir)
        {
            if (string.IsNullOrWhiteSpace(baseDir) || !Directory.Exists(baseDir)) return;
            foreach (string profile in SafeEnumerateDirectories(baseDir).Take(100))
            {
                string history = Path.Combine(profile, "places.sqlite");
                if (File.Exists(history)) sources.Add(new BrowserHistorySource { Browser = "Firefox", Profile = Path.GetFileName(profile), HistoryPath = history, StoreType = "Firefox" });
            }
        }

        private static IEnumerable<string> SafeEnumerateDirectories(string dir)
        {
            if (string.IsNullOrWhiteSpace(dir)) yield break;
            string[] dirs = Array.Empty<string>();
            try { dirs = Directory.GetDirectories(dir); } catch { }
            foreach (string child in dirs)
            {
                if (!IsReparsePoint(child)) yield return child;
            }
        }

        private static bool IsReparsePoint(string path)
        {
            try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
            catch { return true; }
        }

        private static bool IsFirefoxSource(BrowserHistorySource source)
        {
            return source != null && (source.StoreType.Equals("Firefox", StringComparison.OrdinalIgnoreCase) || source.Browser.IndexOf("Firefox", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static List<string> BrowserSearchVariants(string token)
        {
            var variants = new List<string>();
            if (string.IsNullOrWhiteSpace(token)) return variants;
            variants.Add(token);
            if (token.Contains(" ")) variants.Add(token.Replace(" ", "+"));
            if (token.Contains(" ")) variants.Add(token.Replace(" ", "%20"));
            if (token.Contains(" ")) variants.Add(token.Replace(" ", "-"));
            if (token.Contains(".")) variants.Add(token.Replace(".", "[.]"));
            return variants.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static void DeduplicateBrowserMatches(List<BrowserHistoryMatch> matches)
        {
            var merged = matches
                .GroupBy(m => BrowserHistoryMergeKey(m), StringComparer.OrdinalIgnoreCase)
                .Select(g => MergeBrowserHistoryMatches(g.ToList()))
                .ToList();
            matches.Clear();
            matches.AddRange(merged);
        }

        private static void DeduplicateBrowserDownloads(List<BrowserDownloadMatch> matches)
        {
            var merged = matches
                .GroupBy(m => BrowserDownloadMergeKey(m), StringComparer.OrdinalIgnoreCase)
                .Select(g => MergeBrowserDownloadMatches(g.ToList()))
                .ToList();
            matches.Clear();
            matches.AddRange(merged);
        }

        private static string BrowserHistoryMergeKey(BrowserHistoryMatch match)
        {
            return JoinNonBlank(match.Browser, match.Profile, ExtractBrowserItemKey(match.Snippet), match.When);
        }

        private static string BrowserDownloadMergeKey(BrowserDownloadMatch match)
        {
            string urlKey = NormalizeBrowserDownloadUrlForMerge(match.Url);
            string localKey = NormalizeBrowserLocalPathForMerge(match.LocalPath);
            if (!string.IsNullOrWhiteSpace(urlKey) || !string.IsNullOrWhiteSpace(localKey))
                return JoinNonBlank(urlKey, localKey);
            return JoinNonBlank(match.Browser, match.Profile, ExtractBrowserItemKey(match.Snippet));
        }


        private static string NormalizeBrowserDownloadUrlForMerge(string value)
        {
            string url = CleanUrlCandidate(value ?? "");
            if (string.IsNullOrWhiteSpace(url)) return "";
            try
            {
                var uri = new Uri(url);
                string query = uri.Query ?? "";
                if (!string.IsNullOrWhiteSpace(query))
                {
                    var match = Regex.Match(query, @"(?:^|[?&])id=([^&]+)", RegexOptions.IgnoreCase);
                    if (match.Success) return uri.Host.ToLowerInvariant() + uri.AbsolutePath.ToLowerInvariant() + "?id=" + match.Groups[1].Value.ToLowerInvariant();
                }
                return uri.Host.ToLowerInvariant() + uri.AbsolutePath.TrimEnd('/').ToLowerInvariant() + query.ToLowerInvariant();
            }
            catch
            {
                return ScannerHelpers.ToLowerSafe(url.TrimEnd('/'));
            }
        }

        private static string NormalizeBrowserLocalPathForMerge(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "";
            return Regex.Replace(value.Trim(), @"\s+", " ").TrimEnd('\\', '/').ToLowerInvariant();
        }

        private static BrowserHistoryMatch MergeBrowserHistoryMatches(List<BrowserHistoryMatch> items)
        {
            var best = items.OrderByDescending(m => m.Severity).ThenByDescending(m => m.Confidence).ThenByDescending(m => m.Score).First();
            best.Token = JoinLimited(items.Select(m => m.Token), 6);
            best.Label = CombineReasons(items.Select(m => m.Label));
            bool hasStrongSignal = items.Any(m => IsStrongBrowserSignal(m.Token, m.Label, m.Snippet));
            best.Severity = hasStrongSignal ? items.Max(m => m.Severity) : Severity.Low;
            best.Confidence = hasStrongSignal ? items.Max(m => m.Confidence) : Math.Min(44, items.Max(m => m.Confidence));
            best.Score = hasStrongSignal ? Math.Min(90, items.Max(m => m.Score) + Math.Min(16, Math.Max(0, items.Count - 1) * 4)) : Math.Min(4, items.Max(m => m.Score));
            return best;
        }

        private static BrowserDownloadMatch MergeBrowserDownloadMatches(List<BrowserDownloadMatch> items)
        {
            var best = items.OrderByDescending(m => m.Severity).ThenByDescending(m => m.Confidence).ThenByDescending(m => m.Score).First();
            best.Token = JoinLimited(items.Select(m => m.Token), 6);
            best.Label = CombineReasons(items.Select(m => m.Label));
            bool hasStrongSignal = items.Any(m => IsStrongBrowserSignal(m.Token, m.Label, JoinNonBlank(m.Snippet, m.Url, m.LocalPath)));
            best.Severity = hasStrongSignal ? items.Max(m => m.Severity) : Severity.Low;
            best.Confidence = hasStrongSignal ? items.Max(m => m.Confidence) : Math.Min(44, items.Max(m => m.Confidence));
            best.Score = hasStrongSignal ? Math.Min(90, items.Max(m => m.Score) + Math.Min(16, Math.Max(0, items.Count - 1) * 4)) : Math.Min(4, items.Max(m => m.Score));
            return best;
        }

        private static FileNameRule BuildBrowserDomainRule(string url, bool sourceOrDownload)
        {
            string domain = NormalizeDomain(DomainFromUrl(url));
            if (string.IsNullOrWhiteSpace(domain) || IsSelfNoiseBrowserEvidence(url) || IsKnownBenignBrowserEvidence(url) || IsLegitBrowserReviewContext(url) || !IsCheatSiteDomain(domain)) return null;
            return new FileNameRule
            {
                Token = domain,
                Category = sourceOrDownload ? "Browser Source/Download Evidence" : "Browser History",
                Label = sourceOrDownload ? "Browser source/download points to cheat site/domain" : "Browser history shows cheat site/domain",
                Severity = Severity.High,
                Confidence = 86,
                Score = 52
            };
        }

        private static FileNameRule TuneBrowserRule(FileNameRule rule, string evidenceValue, bool hasLocalPath, bool actualDownloadRecord)
        {
            if (rule == null) return null;
            string token = ScannerHelpers.ToLowerSafe(rule.Token);
            string value = ScannerHelpers.ToLowerSafe(evidenceValue);
            if (IsSelfNoiseBrowserEvidence(value) || IsKnownBenignBrowserEvidence(value)) return null;
            bool standaloneBypass = token.Equals("bypass", StringComparison.OrdinalIgnoreCase) && !HasBypassCheatContext(value);
            bool legitContext = IsLegitBrowserReviewContext(value);
            bool strongContext = !legitContext && (BrowserHasStrongContext(value) || hasLocalPath || actualDownloadRecord);
            bool directTerm = !legitContext && (IsStrongBrowserToken(token) || BrowserHasDirectCheatTerm(value));
            bool strongToken = IsStrongBrowserToken(token);
            bool weakToken = !directTerm && (IsWeakBrowserToken(token) || IsWeakBrowserLabel(rule.Label));

            if (standaloneBypass)
            {
                return new FileNameRule
                {
                    Token = rule.Token,
                    Category = rule.Category,
                    Label = "Context-needed browser hit",
                    Severity = Severity.Low,
                    Confidence = Math.Min(rule.Confidence, 44),
                    Score = Math.Min(rule.Score, 4)
                };
            }

            if (legitContext && !hasLocalPath && !actualDownloadRecord)
            {
                return new FileNameRule
                {
                    Token = rule.Token,
                    Category = rule.Category,
                    Label = "Context-needed browser hit",
                    Severity = Severity.Low,
                    Confidence = Math.Min(rule.Confidence, 44),
                    Score = Math.Min(rule.Score, 4)
                };
            }

            if (directTerm || (strongToken && strongContext))
            {
                return new FileNameRule
                {
                    Token = rule.Token,
                    Category = rule.Category,
                    Label = rule.Label,
                    Severity = Severity.High,
                    Confidence = Math.Max(rule.Confidence, 78),
                    Score = Math.Max(rule.Score, 38)
                };
            }

            if (weakToken && !strongContext)
            {
                return new FileNameRule
                {
                    Token = rule.Token,
                    Category = rule.Category,
                    Label = "Context-needed browser hit",
                    Severity = Severity.Low,
                    Confidence = Math.Min(rule.Confidence, 44),
                    Score = Math.Min(rule.Score, 4)
                };
            }

            return rule;
        }

        private static bool IsStrongBrowserSignal(string token, string label, string evidenceValue)
        {
            string joined = ScannerHelpers.ToLowerSafe(JoinNonBlank(token, label, evidenceValue));
            if (IsSelfNoiseBrowserEvidence(joined) || IsKnownBenignBrowserEvidence(joined) || IsLegitBrowserReviewContext(joined)) return false;

            string l = ScannerHelpers.ToLowerSafe(label);
            string t = ScannerHelpers.ToLowerSafe(token);
            if ((t.Equals("bypass", StringComparison.OrdinalIgnoreCase) || t.Contains("bypass")) && !HasBypassCheatContext(joined)) return false;
            return ContainsCheatSiteDomain(joined) ||
                   BrowserHasDirectCheatTerm(joined) ||
                   BrowserHasExplicitCheatToolContext(joined) ||
                   StrongBrowserLabelMatches(l, joined);
        }

        private static bool StrongBrowserLabelMatches(string label, string evidenceValue)
        {
            string l = ScannerHelpers.ToLowerSafe(label);
            if (l.Contains("bypass") && !HasBypassCheatContext(evidenceValue)) return false;
            return l.Contains("cheat site/domain") ||
                   l.Contains("injector") ||
                   l.Contains("mapper") ||
                   l.Contains("spoofer") ||
                   l.Contains("game cheat") ||
                   l.Contains("game-specific cheat") ||
                   l.Contains("cheat feature") ||
                   l.Contains("direct cheat term");
        }

        private static bool BrowserHasExplicitCheatToolContext(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            return BrowserContainsAny(v, ExplicitCheatContextTerms);
        }

        private static bool BrowserHasDirectCheatTerm(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            if (IsSelfNoiseBrowserEvidence(v) || IsKnownBenignBrowserEvidence(v) || IsLegitBrowserReviewContext(v)) return false;
            return BrowserContainsAny(v, DirectBrowserCheatTerms);
        }

        private static bool IsLegitBrowserReviewContext(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            if (string.IsNullOrWhiteSpace(v)) return false;
            if (!BrowserContainsAny(v, LegitReviewContextTerms)) return false;
            return !BrowserContainsAny(v, LegitReviewOverrideTerms);
        }

        private static bool BrowserContainsAny(string value, IEnumerable<string> tokens)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            if (string.IsNullOrWhiteSpace(v) || tokens == null) return false;
            return tokens.Any(t => BrowserTokenMatches(v, t));
        }

        private static bool BrowserTokenMatches(string haystack, string token)
        {
            if (string.IsNullOrWhiteSpace(haystack) || string.IsNullOrWhiteSpace(token)) return false;
            if (TokenNeedsBrowserBoundary(token)) return Regex.IsMatch(haystack, @"(?<![a-z0-9])" + Regex.Escape(token) + @"(?![a-z0-9])", RegexOptions.IgnoreCase);
            return haystack.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool TokenNeedsBrowserBoundary(string token)
        {
            string t = ScannerHelpers.ToLowerSafe(token);
            if (t.Length <= 5 && t.IndexOf('.') < 0) return true;
            return IsWeakBrowserToken(t);
        }

        private static bool BrowserHasStrongContext(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            return ContainsCheatSiteDomain(v) ||
                   BrowserContainsAny(v, StrongBrowserContextTerms) ||
                   BrowserHasDirectCheatTerm(v) ||
                   BrowserHasExplicitCheatToolContext(v);
        }

        private static bool IsStrongBrowserToken(string token)
        {
            string t = NormalizeDomain(token);
            if (IsCheatSiteDomain(t)) return true;
            return DirectBrowserCheatTerms.Any(x => string.Equals(x, token, StringComparison.OrdinalIgnoreCase)) ||
                   ExplicitCheatContextTerms.Any(x => string.Equals(x, token, StringComparison.OrdinalIgnoreCase));
        }

        private static bool ContainsCheatSiteDomain(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            foreach (Match match in Regex.Matches(v, @"https?://[^\s|<>""']+", RegexOptions.IgnoreCase))
            {
                if (IsCheatSiteDomain(NormalizeDomain(DomainFromUrl(match.Value)))) return true;
            }

            foreach (string domain in CheatSiteDomains())
            {
                if (DomainTextContains(v, domain)) return true;
            }

            return false;
        }

        private static bool IsCheatSiteDomain(string domain)
        {
            string d = NormalizeDomain(domain);
            if (string.IsNullOrWhiteSpace(d)) return false;
            foreach (string known in CheatSiteDomains())
            {
                string k = NormalizeDomain(known);
                if (d.Equals(k, StringComparison.OrdinalIgnoreCase) || d.EndsWith("." + k, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return DomainLooksCheatRelated(d);
        }

        private static bool DomainTextContains(string value, string domain)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            string d = NormalizeDomain(domain);
            if (string.IsNullOrWhiteSpace(v) || string.IsNullOrWhiteSpace(d)) return false;
            return Regex.IsMatch(v, @"(?<![a-z0-9])" + Regex.Escape(d) + @"(?![a-z0-9])", RegexOptions.IgnoreCase);
        }

        private static string NormalizeDomain(string domain)
        {
            string d = ScannerHelpers.ToLowerSafe(domain).Trim();
            if (d.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || d.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) d = DomainFromUrl(d);
            if (d.StartsWith("www.", StringComparison.OrdinalIgnoreCase)) d = d.Substring(4);
            return d.Trim('/').Trim();
        }

        private static bool DomainLooksCheatRelated(string domain)
        {
            string compact = Regex.Replace(domain ?? "", @"[^a-z0-9]", "");
            if (string.IsNullOrWhiteSpace(compact)) return false;
            if (ReviewDomainContextTerms.Any(t => compact.Contains(t)))
            {
                string reviewCompact = compact;
                foreach (string token in ReviewDomainContextTerms)
                {
                    reviewCompact = reviewCompact.Replace(token, "");
                }
                if (!CheatDomainTerms.Any(t => reviewCompact.Contains(t))) return false;
            }
            return CheatDomainTerms.Any(t => compact.Contains(t));
        }

        private static IEnumerable<string> CheatSiteDomains()
        {
            return new[]
            {
                "unknowncheats.me", "guidedhacking.com", "elitepvpers.com", "mpgh.net", "yougame.biz", "cosmocheats.com", "lethality.club", "evicted.wtf", "cheatprovider.store", "burgercheats.com", "team073.com", "spyderrz.com", "beaztcheats.com", "suspectcheats.com", "lexshop.xyz", "shxdowcheats.net", "ssz.gg", "apexdma.xyz", "sapphire-service.shop", "only-cheats.com", "deprimereshop.com", "kernaim.to", "disconnect.wtf", "disconnectcheats.com", "aimjunkies.com", "artificialaiming.net", "klar.gg", "phantomoverlay.io", "engineowning.to", "iwantcheats.net", "systemcheats.com", "ring-1.io", "proofcore.io", "securecheats.com", "skycheats.com", "x22cheats.com", "battlelog.co", "cheater.fun", "cheats.com", "cheats.net", "cheats.gg", "cheats.xyz", "cheat.shop", "cheat.store"
            };
        }

        private static bool IsWeakBrowserToken(string token)
        {
            return WeakBrowserTokens.Any(t => string.Equals(t, token, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsWeakBrowserLabel(string label)
        {
            string v = ScannerHelpers.ToLowerSafe(label);
            return v.Contains("weak keyword") || v.Contains("context-needed") || v.Contains("source / build / sdk") || v.Contains("provider / project") || v.Contains("brand / project");
        }

        private static bool LooksLikeDownloadUrl(string url)
        {
            string v = ScannerHelpers.ToLowerSafe(url);
            return DownloadUrlTerms.Any(t => v.Contains(t));
        }

        private static string ExtractBrowserItemKey(string snippet)
        {
            string value = snippet ?? "";
            int index = value.IndexOf(" | ", StringComparison.Ordinal);
            if (index > 0) return value.Substring(0, index).Trim();
            return value.Trim();
        }

        private static string CombineReasons(IEnumerable<string> labels)
        {
            var reasons = (labels ?? Enumerable.Empty<string>())
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .Select(l => l.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(4)
                .ToList();
            if (reasons.Count <= 1) return reasons.Count == 0 ? "Browser evidence" : reasons[0];
            return "Multiple browser signals: " + string.Join("; ", reasons);
        }

        private static string JoinLimited(IEnumerable<string> values, int limit)
        {
            return string.Join(", ", (values ?? Enumerable.Empty<string>()).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Take(Math.Max(1, limit)));
        }

        private static bool IsSelfNoiseBrowserEvidence(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            if (string.IsNullOrWhiteSpace(v)) return false;
            if (ScannerHelpers.IsGamerIntegritySelfNoise(v)) return true;

            bool gamerIntegrityContext = v.Contains("gamerintegrity") || v.Contains("gamer integrity") || v.Contains("gamer integrity report") || v.Contains("dayzeroanticheat") || v.Contains("dayzero anticheat") || v.Contains("pc checker for gamers") || v.Contains("integrity report");
            if (gamerIntegrityContext) return true;

            bool localReport = v.Contains("file:///") && (v.Contains("gamerintegrity_report.html") || v.Contains("gamerintegrity_report.json") || v.Contains("\\gamerintegrity\\") || v.Contains("/gamerintegrity/"));
            if (localReport) return true;

            bool chatgptDevelopment = v.Contains("chatgpt.com") &&
                (v.Contains("dma device detection limitations") || v.Contains("stability performance pass") || v.Contains("modern c# theme") || v.Contains("c# application conversion") || v.Contains("code review feedback") || v.Contains("external device history update") || v.Contains("github page") || v.Contains("github release") || v.Contains("report layout") || v.Contains("wiki styled"));
            if (chatgptDevelopment) return true;

            bool gamerIntegrityArchive = v.Contains("gamerintegrity") && (v.Contains(".zip") || v.Contains("source") || v.Contains("release") || v.Contains("github.io"));
            return gamerIntegrityArchive;
        }

        private static bool IsKnownBenignBrowserEvidence(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            if (string.IsNullOrWhiteSpace(v)) return false;
            if ((v.Contains("pandora.com") || v.Contains("www.pandora.com")) && !ContainsCheatSiteDomain(v)) return true;
            return false;
        }

        private static bool HasBypassCheatContext(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            if (string.IsNullOrWhiteSpace(v)) return false;
            if (ContainsCheatSiteDomain(v)) return true;
            string[] context =
            {
                "anti-cheat", "anticheat", "eac", "easy anti-cheat", "battleye", "battl-eye", "vanguard", "vgk", "vgc", "faceit", "ricochet",
                "vac", "ban", "unban", "hwid", "spoofer", "spoof", "driver", "kernel", "mapper", "kdmapper", "injector", "dse", "patchguard",
                "valorant", "fortnite", "apex", "warzone", "cod", "rust", "tarkov", "eft", "cs2", "counter-strike", "roblox", "fivem",
                "cheat", "cheats", "hack", "hacks", "loader"
            };
            return context.Any(t => BrowserTokenMatches(v, t));
        }

        private static bool IsKnownBenignBrowserDownloadMatch(BrowserDownloadMatch match)
        {
            string domain = ScannerHelpers.ToLowerSafe(match.Domain);
            string url = ScannerHelpers.ToLowerSafe(match.Url);
            string local = ScannerHelpers.ToLowerSafe(match.LocalPath);
            string file = ScannerHelpers.ToLowerSafe(ScannerHelpers.GetFileNameOnly(match.LocalPath));
            string token = ScannerHelpers.ToLowerSafe(match.Token);
            if (IsSelfNoiseBrowserEvidence(url + " " + local + " " + match.Snippet) || IsKnownBenignBrowserEvidence(url + " " + local + " " + match.Snippet)) return true;
            bool microsoftDomain = domain == "microsoft.com" || domain == "www.microsoft.com" || domain == "download.microsoft.com" || domain == "aka.ms" || domain.EndsWith(".microsoft.com", StringComparison.OrdinalIgnoreCase);
            if (microsoftDomain && (file.Contains("vcredist") || file.Contains("directx") || file.Contains("dxwebsetup") || file.Contains("dotnet"))) return true;
            if ((token == "loader" || token == "cheat.com" || token == "cheats.com") && microsoftDomain && !ContainsAnySuspiciousBrowserToken(url + " " + local)) return true;
            return false;
        }

        private static bool ContainsAnySuspiciousBrowserToken(string value)
        {
            string v = ScannerHelpers.ToLowerSafe(value);
            string[] tokens = { "aimbot", "triggerbot", "wallhack", "kdmapper", "injector", "spoofer", "cheat provider", "cheat-loader", "cheatloader" };
            return ContainsCheatSiteDomain(v) || tokens.Any(t => v.Contains(t));
        }

        private static string BuildDisplaySnippet(params string[] parts)
        {
            return ScannerHelpers.CollapseWhitespaceForDisplay(JoinNonBlank(parts));
        }

        private static string JoinNonBlank(params string[] parts)
        {
            return string.Join(" | ", (parts ?? Array.Empty<string>()).Where(p => !string.IsNullOrWhiteSpace(p)));
        }

        private static string FirstNonBlank(params string[] values)
        {
            foreach (string value in values ?? Array.Empty<string>())
            {
                if (!string.IsNullOrWhiteSpace(value)) return value;
            }
            return "";
        }

        private static string GetDownloadChain(Dictionary<long, string> map, long id)
        {
            string value;
            return id > 0 && map.TryGetValue(id, out value) ? value : "";
        }

        private static bool SameSource(BrowserHistoryMatch match, BrowserHistorySource source)
        {
            return match != null && source != null && string.Equals(match.HistoryPath, source.HistoryPath, StringComparison.OrdinalIgnoreCase);
        }

        private static bool SameSource(BrowserDownloadMatch match, BrowserHistorySource source)
        {
            return match != null && source != null && string.Equals(match.HistoryPath, source.HistoryPath, StringComparison.OrdinalIgnoreCase);
        }

        private static string ConvertBrowserTime(long value, string storeType)
        {
            try
            {
                if (value <= 0) return "";
                DateTimeOffset utc;
                if (string.Equals(storeType, "Firefox", StringComparison.OrdinalIgnoreCase))
                {
                    utc = DateTimeOffset.FromUnixTimeMilliseconds(value / 1000);
                }
                else
                {
                    var epoch = new DateTimeOffset(1601, 1, 1, 0, 0, 0, TimeSpan.Zero);
                    utc = epoch.AddTicks(value * 10);
                }
                return utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture);
            }
            catch { return ""; }
        }

        private static string NormalizeFirefoxLocalPath(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "";
            string v = value.Trim();
            if (v.StartsWith("file:///", StringComparison.OrdinalIgnoreCase))
            {
                try { return Uri.UnescapeDataString(new Uri(v).LocalPath); }
                catch { return Uri.UnescapeDataString(v.Substring("file:///".Length)).Replace('/', '\\'); }
            }
            return v;
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

        private static string CleanExceptionMessage(Exception ex)
        {
            if (ex == null) return "Unknown error";
            string message = ex.Message ?? ex.GetType().Name;
            return ScannerHelpers.CollapseWhitespaceForDisplay(message);
        }

        private static string GetString(SqliteDataReader reader, string name)
        {
            try
            {
                int ordinal = reader.GetOrdinal(name);
                if (ordinal < 0 || reader.IsDBNull(ordinal)) return "";
                return Convert.ToString(reader.GetValue(ordinal), CultureInfo.InvariantCulture) ?? "";
            }
            catch { return ""; }
        }

        private static long GetInt64(SqliteDataReader reader, string name)
        {
            try
            {
                int ordinal = reader.GetOrdinal(name);
                if (ordinal < 0 || reader.IsDBNull(ordinal)) return 0;
                object value = reader.GetValue(ordinal);
                if (value is long l) return l;
                if (value is int i) return i;
                long parsed;
                return long.TryParse(Convert.ToString(value, CultureInfo.InvariantCulture), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed) ? parsed : 0;
            }
            catch { return 0; }
        }

        private static void TryDelete(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            try { if (File.Exists(path)) File.Delete(path); } catch { }
            try { if (File.Exists(path + "-wal")) File.Delete(path + "-wal"); } catch { }
            try { if (File.Exists(path + "-shm")) File.Delete(path + "-shm"); } catch { }
        }

        private sealed class BrowserSqlRow
        {
            public long DownloadId;
            public string Url = "";
            public string SecondaryUrl = "";
            public string Title = "";
            public string CurrentPath = "";
            public string TargetPath = "";
            public string When = "";
        }
    }
}
