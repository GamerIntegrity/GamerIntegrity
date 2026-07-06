using System;
using System.Collections.Generic;
using System.Linq;

namespace GamerIntegrity
{
    public sealed class KnownVulnerableDriverMatch
    {
        public string CatalogVersion { get; set; } = "";
        public string RuleId { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string Description { get; set; } = "";
        public string MatchedBy { get; set; } = "";
        public string MatchedValue { get; set; } = "";
        public Severity Severity { get; set; } = Severity.Info;
        public int Confidence { get; set; }
    }

    internal sealed class KnownVulnerableDriverRule
    {
        public string Id { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string Description { get; set; } = "";
        public string[] FileNames { get; set; } = new string[0];
        public string[] ServiceNames { get; set; } = new string[0];
        public string[] CompanyTokens { get; set; } = new string[0];
        public string[] ProductTokens { get; set; } = new string[0];
        public string[] Sha256Hashes { get; set; } = new string[0];
    }

    public static class KnownVulnerableDriverCatalog
    {
        public const string Version = "embedded-v2026.07.06";

        private static readonly KnownVulnerableDriverRule[] Rules = new[]
        {
            Rule("intel-iqvw64", "Intel network diagnostics driver", "Commonly abused BYOVD driver family used by mapper/tooling chains.",
                new[] { "iqvw64e.sys", "iqvw32.sys", "iqvw64.sys" },
                new[] { "iqvw64e", "iqvw32", "iqvw64" },
                new[] { "intel" },
                new[] { "network", "diagnostic", "adapter" }),

            Rule("capcom", "Capcom vulnerable driver", "Known vulnerable Capcom driver indicator.",
                new[] { "capcom.sys" },
                new[] { "capcom" },
                new[] { "capcom" },
                new[] { "capcom" }),

            Rule("gigabyte-gdrv", "GIGABYTE vulnerable driver family", "GIGABYTE driver family often reviewed in BYOVD/mapper investigations.",
                new[] { "gdrv.sys", "gdrv2.sys", "gdrv3.sys" },
                new[] { "gdrv", "gdrv2", "gdrv3" },
                new[] { "gigabyte" },
                new[] { "gigabyte", "app center" }),

            Rule("dell-dbutil", "Dell DBUtil driver family", "Dell DBUtil driver family with known vulnerable-driver history.",
                new[] { "dbutil_2_3.sys", "dbutil_2_5.sys", "dbutildrv2.sys", "dbutil.sys" },
                new[] { "dbutil_2_3", "dbutil_2_5", "dbutildrv2", "dbutil" },
                new[] { "dell" },
                new[] { "dbutil", "dell" }),

            Rule("msi-rtcore", "MSI RTCore / Afterburner driver family", "MSI RTCore-style driver family commonly checked in vulnerable-driver reviews.",
                new[] { "rtcore64.sys", "rtcore32.sys", "rtcore.sys", "msio64.sys", "msio32.sys", "ntiolib_x64.sys", "ntiolib.sys" },
                new[] { "rtcore64", "rtcore32", "rtcore", "msio64", "msio32", "ntiolib_x64", "ntiolib" },
                new[] { "micro-star", "msi", "nticorp", "ami" },
                new[] { "afterburner", "command center", "msi" }),

            Rule("eneio", "ENE IO driver family", "ENE IO driver family often checked because vulnerable versions are abused by BYOVD tooling.",
                new[] { "eneio64.sys", "eneio.sys", "ene.sys" },
                new[] { "eneio64", "eneio", "ene" },
                new[] { "ene technology", "ene" },
                new[] { "ene", "rgb" }),

            Rule("winring0", "WinRing0 / OpenLibSys driver family", "WinRing0/OpenLibSys driver family commonly reviewed in vulnerable-driver and hardware-access chains.",
                new[] { "winring0x64.sys", "winring0.sys", "winring0_1_2_0.sys", "winring0x64_1_2_0.sys" },
                new[] { "winring0", "winring0x64" },
                new[] { "openlibsys", "open libsys" },
                new[] { "winring0", "openlibsys" }),

            Rule("asrock-asrdrv", "ASRock low-level driver family", "ASRock low-level driver family included for vulnerable-driver review context.",
                new[] { "asrdrv.sys", "asrdrv10.sys", "asrdrv101.sys", "asrdrv102.sys", "asrdrv103.sys", "asrdrv104.sys" },
                new[] { "asrdrv", "asrdrv10", "asrdrv101", "asrdrv102", "asrdrv103", "asrdrv104" },
                new[] { "asrock" },
                new[] { "asrock" }),

            Rule("asus-asio", "ASUS IO driver family", "ASUS low-level IO driver family included for vulnerable-driver review context.",
                new[] { "asio.sys", "asio2.sys", "asupio.sys", "asushwio.sys" },
                new[] { "asio", "asio2", "asupio", "asushwio" },
                new[] { "asus", "asustek" },
                new[] { "asus", "ai suite", "armoury" }),

            Rule("mhyprot", "miHoYo protection driver family", "miHoYo protection driver family has known vulnerable-driver abuse history and should be reviewed when present.",
                new[] { "mhyprot2.sys", "mhyprotect.sys", "mhyprot.sys" },
                new[] { "mhyprot2", "mhyprotect", "mhyprot" },
                new[] { "mihoyo", "hoyoverse" },
                new[] { "mhyprot", "mihoyo", "hoyoverse" }),

            Rule("inpout", "InpOut driver family", "InpOut driver family can provide low-level hardware access and is reviewed in driver-abuse investigations.",
                new[] { "inpoutx64.sys", "inpout32.sys", "inpout.sys" },
                new[] { "inpoutx64", "inpout32", "inpout" },
                new[] { "highresolution", "logix4u" },
                new[] { "inpout" })
        };

        public static int RuleCount { get { return Rules.Length; } }

        public static KnownVulnerableDriverMatch Evaluate(DriverInfo driver)
        {
            if (driver == null) return null;

            string fileName = NormalizeFileName(driver.Name);
            string originalFileName = NormalizeFileName(driver.OriginalFileName);
            string serviceName = NormalizeToken(driver.Service == null ? "" : driver.Service.ServiceName);
            string company = NormalizeToken(driver.Company);
            string product = NormalizeToken(driver.ProductName);
            string pathFileName = NormalizeFileName(System.IO.Path.GetFileName(driver.Path ?? ""));
            string hash = NormalizeHash(driver.Sha256);

            foreach (var rule in Rules)
            {
                if (!string.IsNullOrWhiteSpace(hash) && rule.Sha256Hashes.Any(h => string.Equals(NormalizeHash(h), hash, StringComparison.OrdinalIgnoreCase)))
                {
                    return BuildMatch(rule, "SHA-256 hash", hash, Severity.High, 94);
                }

                string matchedFile = MatchAnyFile(rule.FileNames, fileName, originalFileName, pathFileName);
                bool serviceMatch = MatchesAny(rule.ServiceNames, serviceName);
                bool companyMatch = ContainsAny(company, rule.CompanyTokens);
                bool productMatch = ContainsAny(product, rule.ProductTokens);

                if (!string.IsNullOrWhiteSpace(matchedFile) && (serviceMatch || companyMatch || productMatch))
                {
                    string context = serviceMatch ? "service" : (companyMatch ? "company" : "product");
                    return BuildMatch(rule, "filename + " + context, matchedFile, Severity.High, 86);
                }

                if (!string.IsNullOrWhiteSpace(matchedFile))
                {
                    return BuildMatch(rule, "filename", matchedFile, Severity.Medium, 72);
                }

                if (serviceMatch && (companyMatch || productMatch))
                {
                    return BuildMatch(rule, "service + vendor/product", serviceName, Severity.Medium, 72);
                }

                if (serviceMatch)
                {
                    return BuildMatch(rule, "service", serviceName, Severity.Low, 58);
                }
            }

            return null;
        }

        private static KnownVulnerableDriverRule Rule(string id, string displayName, string description, string[] fileNames, string[] serviceNames, string[] companyTokens, string[] productTokens)
        {
            return new KnownVulnerableDriverRule
            {
                Id = id,
                DisplayName = displayName,
                Description = description,
                FileNames = fileNames ?? new string[0],
                ServiceNames = serviceNames ?? new string[0],
                CompanyTokens = companyTokens ?? new string[0],
                ProductTokens = productTokens ?? new string[0],
                Sha256Hashes = new string[0]
            };
        }

        private static KnownVulnerableDriverMatch BuildMatch(KnownVulnerableDriverRule rule, string matchedBy, string matchedValue, Severity severity, int confidence)
        {
            return new KnownVulnerableDriverMatch
            {
                CatalogVersion = Version,
                RuleId = rule.Id,
                DisplayName = rule.DisplayName,
                Description = rule.Description,
                MatchedBy = matchedBy,
                MatchedValue = matchedValue,
                Severity = severity,
                Confidence = confidence
            };
        }

        private static string MatchAnyFile(IEnumerable<string> tokens, params string[] values)
        {
            foreach (string token in tokens ?? new string[0])
            {
                string normalized = NormalizeFileName(token);
                if (string.IsNullOrWhiteSpace(normalized)) continue;
                foreach (string value in values ?? new string[0])
                {
                    if (string.Equals(NormalizeFileName(value), normalized, StringComparison.OrdinalIgnoreCase)) return normalized;
                }
            }
            return "";
        }

        private static bool MatchesAny(IEnumerable<string> tokens, string value)
        {
            string v = NormalizeToken(value);
            return (tokens ?? new string[0]).Any(t => string.Equals(NormalizeToken(t), v, StringComparison.OrdinalIgnoreCase));
        }

        private static bool ContainsAny(string value, IEnumerable<string> tokens)
        {
            string v = NormalizeToken(value);
            if (string.IsNullOrWhiteSpace(v)) return false;
            foreach (string token in tokens ?? new string[0])
            {
                string t = NormalizeToken(token);
                if (!string.IsNullOrWhiteSpace(t) && v.Contains(t)) return true;
            }
            return false;
        }

        private static string NormalizeFileName(string value)
        {
            return NormalizeToken(value).Trim().Trim('"').Trim();
        }

        private static string NormalizeHash(string value)
        {
            return NormalizeToken(value).Replace(" ", "").Replace("-", "");
        }

        private static string NormalizeToken(string value)
        {
            return (value ?? "").Trim().ToLowerInvariant();
        }
    }
}
