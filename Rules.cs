using System;
using System.Collections.Generic;

namespace GamerIntegrity
{
    public static class Rules
    {
        public static List<FileNameRule> FileNameRules()
        {
            var rules = new List<FileNameRule>
            {
                new FileNameRule { Token = @"cheat source", Category = @"File Name Scan", Label = @"Cheat source/code artifact detected", Severity = Severity.Critical, Confidence = 90, Score = 80 },
                new FileNameRule { Token = @"cheat src", Category = @"File Name Scan", Label = @"Cheat source/code artifact detected", Severity = Severity.Critical, Confidence = 88, Score = 75 },
                new FileNameRule { Token = @"hack source", Category = @"File Name Scan", Label = @"Cheat source/code artifact detected", Severity = Severity.Critical, Confidence = 88, Score = 75 },
                new FileNameRule { Token = @"hack src", Category = @"File Name Scan", Label = @"Cheat source/code artifact detected", Severity = Severity.Critical, Confidence = 86, Score = 70 },
                new FileNameRule { Token = @"aimbot source", Category = @"File Name Scan", Label = @"Cheat source/code artifact detected", Severity = Severity.Critical, Confidence = 92, Score = 85 },
                new FileNameRule { Token = @"aimbot src", Category = @"File Name Scan", Label = @"Cheat source/code artifact detected", Severity = Severity.Critical, Confidence = 90, Score = 80 },
                new FileNameRule { Token = @"wallhack source", Category = @"File Name Scan", Label = @"Cheat source/code artifact detected", Severity = Severity.Critical, Confidence = 92, Score = 85 },
                new FileNameRule { Token = @"esp source", Category = @"File Name Scan", Label = @"Cheat source/code artifact detected", Severity = Severity.Critical, Confidence = 88, Score = 75 },
                new FileNameRule { Token = @"external cheat", Category = @"File Name Scan", Label = @"Cheat project/source folder detected", Severity = Severity.High, Confidence = 86, Score = 65 },
                new FileNameRule { Token = @"internal cheat", Category = @"File Name Scan", Label = @"Cheat project/source folder detected", Severity = Severity.High, Confidence = 86, Score = 65 },
                new FileNameRule { Token = @"cheat loader", Category = @"File Name Scan", Label = @"Cheat loader/source artifact detected", Severity = Severity.High, Confidence = 84, Score = 60 },
                new FileNameRule { Token = @"cheat menu", Category = @"File Name Scan", Label = @"Cheat UI/menu artifact detected", Severity = Severity.High, Confidence = 82, Score = 55 },
                new FileNameRule { Token = @"cheat overlay", Category = @"File Name Scan", Label = @"Cheat overlay artifact detected", Severity = Severity.High, Confidence = 82, Score = 55 },
                new FileNameRule { Token = @"game cheat", Category = @"File Name Scan", Label = @"Cheat project/source folder detected", Severity = Severity.High, Confidence = 84, Score = 60 },
                new FileNameRule { Token = @"cs2 cheat", Category = @"File Name Scan", Label = @"Game cheat project detected", Severity = Severity.High, Confidence = 86, Score = 65 },
                new FileNameRule { Token = @"csgo cheat", Category = @"File Name Scan", Label = @"Game cheat project detected", Severity = Severity.High, Confidence = 86, Score = 65 },
                new FileNameRule { Token = @"valorant cheat", Category = @"File Name Scan", Label = @"Game cheat project detected", Severity = Severity.High, Confidence = 86, Score = 65 },
                new FileNameRule { Token = @"fortnite cheat", Category = @"File Name Scan", Label = @"Game cheat project detected", Severity = Severity.High, Confidence = 86, Score = 65 },
                new FileNameRule { Token = @"warzone cheat", Category = @"File Name Scan", Label = @"Game cheat project detected", Severity = Severity.High, Confidence = 86, Score = 65 },
                new FileNameRule { Token = @"apex cheat", Category = @"File Name Scan", Label = @"Game cheat project detected", Severity = Severity.High, Confidence = 86, Score = 65 },
                new FileNameRule { Token = @"external esp", Category = @"File Name Scan", Label = @"Cheat feature/project detected", Severity = Severity.High, Confidence = 82, Score = 55 },
                new FileNameRule { Token = @"internal esp", Category = @"File Name Scan", Label = @"Cheat feature/project detected", Severity = Severity.High, Confidence = 82, Score = 55 },
                new FileNameRule { Token = @"overlay esp", Category = @"File Name Scan", Label = @"Cheat feature/project detected", Severity = Severity.High, Confidence = 82, Score = 55 },
                new FileNameRule { Token = @"box esp", Category = @"File Name Scan", Label = @"Cheat feature file/folder detected", Severity = Severity.High, Confidence = 80, Score = 50 },
                new FileNameRule { Token = @"skeleton esp", Category = @"File Name Scan", Label = @"Cheat feature file/folder detected", Severity = Severity.High, Confidence = 80, Score = 50 },
                new FileNameRule { Token = @"driver cheat", Category = @"File Name Scan", Label = @"Kernel cheat project detected", Severity = Severity.High, Confidence = 86, Score = 65 },
                new FileNameRule { Token = @"kernel cheat", Category = @"File Name Scan", Label = @"Kernel cheat project detected", Severity = Severity.High, Confidence = 86, Score = 65 },
                new FileNameRule { Token = @"dma cheat", Category = @"File Name Scan", Label = @"DMA cheat indicator detected", Severity = Severity.High, Confidence = 82, Score = 55 },
                new FileNameRule { Token = @"arduino aimbot", Category = @"File Name Scan", Label = @"External aim-assist tooling detected", Severity = Severity.High, Confidence = 82, Score = 55 },
                new FileNameRule { Token = @"kmbox", Category = @"File Name Scan", Label = @"External input-assist tooling detected", Severity = Severity.Medium, Confidence = 70, Score = 30 },
                new FileNameRule { Token = @"osiris", Category = @"File Name Scan", Label = @"Known public cheat project detected", Severity = Severity.High, Confidence = 78, Score = 45 },
                new FileNameRule { Token = @"nullhooks", Category = @"File Name Scan", Label = @"Known public cheat project detected", Severity = Severity.High, Confidence = 80, Score = 50 },
                new FileNameRule { Token = @"aimtux", Category = @"File Name Scan", Label = @"Known public cheat project detected", Severity = Severity.High, Confidence = 78, Score = 45 },
                new FileNameRule { Token = @"gamesense", Category = @"File Name Scan", Label = @"Known cheat brand/project detected", Severity = Severity.Medium, Confidence = 70, Score = 30 },
                new FileNameRule { Token = @"neverlose", Category = @"File Name Scan", Label = @"Known cheat brand/project detected", Severity = Severity.Medium, Confidence = 70, Score = 30 },
                new FileNameRule { Token = @"onetap", Category = @"File Name Scan", Label = @"Known cheat brand/project detected", Severity = Severity.Medium, Confidence = 70, Score = 30 },
                new FileNameRule { Token = @"fatality", Category = @"File Name Scan", Label = @"Known cheat brand/project detected", Severity = Severity.Medium, Confidence = 65, Score = 25 },
                new FileNameRule { Token = @"primordial", Category = @"File Name Scan", Label = @"Known cheat brand/project detected", Severity = Severity.Medium, Confidence = 65, Score = 25 },
                new FileNameRule { Token = @"legendware", Category = @"File Name Scan", Label = @"Known cheat brand/project detected", Severity = Severity.Medium, Confidence = 70, Score = 30 },
                new FileNameRule { Token = @"interium", Category = @"File Name Scan", Label = @"Known cheat brand/project detected", Severity = Severity.Medium, Confidence = 65, Score = 25 },
                new FileNameRule { Token = @"rifk7", Category = @"File Name Scan", Label = @"Known cheat brand/project detected", Severity = Severity.Medium, Confidence = 70, Score = 30 },
                new FileNameRule { Token = @"hwid spoofer", Category = @"File Name Scan", Label = @"Hardware ID spoofer detected", Severity = Severity.Medium, Confidence = 70, Score = 25 },
                new FileNameRule { Token = @"spoofer", Category = @"File Name Scan", Label = @"Spoofer tool/file detected", Severity = Severity.Medium, Confidence = 60, Score = 20 },
                new FileNameRule { Token = @"trace cleaner", Category = @"File Name Scan", Label = @"Trace-cleaner file detected", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"cleaner", Category = @"File Name Scan", Label = @"Cleaner-related file detected", Severity = Severity.Low, Confidence = 45, Score = 8 },
                new FileNameRule { Token = @"kdmapper", Category = @"File Name Scan", Label = @"Kernel driver mapper detected", Severity = Severity.High, Confidence = 80, Score = 45 },
                new FileNameRule { Token = @"driver mapper", Category = @"File Name Scan", Label = @"Kernel driver mapper detected", Severity = Severity.High, Confidence = 75, Score = 40 },
                new FileNameRule { Token = @"manual map", Category = @"File Name Scan", Label = @"Manual mapping tool/file detected", Severity = Severity.Medium, Confidence = 65, Score = 22 },
                new FileNameRule { Token = @"manualmap", Category = @"File Name Scan", Label = @"Manual mapping tool/file detected", Severity = Severity.Medium, Confidence = 65, Score = 22 },
                new FileNameRule { Token = @"injector", Category = @"File Name Scan", Label = @"Injector tool/file detected", Severity = Severity.Medium, Confidence = 60, Score = 20 },
                new FileNameRule { Token = @"loader", Category = @"File Name Scan", Label = @"Loader-related file/folder detected", Severity = Severity.Medium, Confidence = 58, Score = 18 },
                new FileNameRule { Token = @"bypass", Category = @"File Name Scan", Label = @"Bypass-related file detected", Severity = Severity.Medium, Confidence = 60, Score = 20 },
                new FileNameRule { Token = @"eac bypass", Category = @"File Name Scan", Label = @"Anti-cheat bypass file detected", Severity = Severity.High, Confidence = 80, Score = 45 },
                new FileNameRule { Token = @"battleye bypass", Category = @"File Name Scan", Label = @"Anti-cheat bypass file detected", Severity = Severity.High, Confidence = 80, Score = 45 },
                new FileNameRule { Token = @"vanguard bypass", Category = @"File Name Scan", Label = @"Anti-cheat bypass file detected", Severity = Severity.High, Confidence = 80, Score = 45 },
                new FileNameRule { Token = @"aimbot", Category = @"File Name Scan", Label = @"Cheat feature file/folder detected", Severity = Severity.High, Confidence = 80, Score = 45 },
                new FileNameRule { Token = @"wallhack", Category = @"File Name Scan", Label = @"Cheat feature file/folder detected", Severity = Severity.High, Confidence = 80, Score = 45 },
                new FileNameRule { Token = @"triggerbot", Category = @"File Name Scan", Label = @"Cheat feature file/folder detected", Severity = Severity.High, Confidence = 80, Score = 45 },
                new FileNameRule { Token = @"ragebot", Category = @"File Name Scan", Label = @"Cheat feature file/folder detected", Severity = Severity.High, Confidence = 80, Score = 45 },
                new FileNameRule { Token = @"silent aim", Category = @"File Name Scan", Label = @"Cheat feature file/folder detected", Severity = Severity.High, Confidence = 75, Score = 40 },
                new FileNameRule { Token = @"no recoil", Category = @"File Name Scan", Label = @"Cheat feature file/folder detected", Severity = Severity.Medium, Confidence = 65, Score = 25 },
                new FileNameRule { Token = @"norecoil", Category = @"File Name Scan", Label = @"Cheat feature file/folder detected", Severity = Severity.Medium, Confidence = 65, Score = 25 },
                new FileNameRule { Token = @"radar hack", Category = @"File Name Scan", Label = @"Cheat feature file/folder detected", Severity = Severity.Medium, Confidence = 65, Score = 25 },
                new FileNameRule { Token = @"glow hack", Category = @"File Name Scan", Label = @"Cheat feature file/folder detected", Severity = Severity.Medium, Confidence = 65, Score = 25 },
                new FileNameRule { Token = @"cheat engine", Category = @"File Name Scan", Label = @"Cheat Engine memory editor detected", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"cheatengine", Category = @"File Name Scan", Label = @"Cheat Engine memory editor detected", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"wemod", Category = @"File Name Scan", Label = @"WeMod game trainer detected", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"x64dbg", Category = @"File Name Scan", Label = @"Game debugging/disassembly tool detected", Severity = Severity.Medium, Confidence = 68, Score = 22 },
                new FileNameRule { Token = @"x32dbg", Category = @"File Name Scan", Label = @"Game debugging/disassembly tool detected", Severity = Severity.Medium, Confidence = 68, Score = 22 },
                new FileNameRule { Token = @"ollydbg", Category = @"File Name Scan", Label = @"Game debugging/disassembly tool detected", Severity = Severity.Medium, Confidence = 68, Score = 22 },
                new FileNameRule { Token = @"ida", Category = @"File Name Scan", Label = @"IDA disassembler detected", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"ida pro", Category = @"File Name Scan", Label = @"IDA disassembler detected", Severity = Severity.Medium, Confidence = 74, Score = 30 },
                new FileNameRule { Token = @"ida32", Category = @"File Name Scan", Label = @"IDA disassembler detected", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"ida64", Category = @"File Name Scan", Label = @"IDA disassembler detected", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"idaw", Category = @"File Name Scan", Label = @"IDA disassembler detected", Severity = Severity.Medium, Confidence = 70, Score = 24 },
                new FileNameRule { Token = @"idaw64", Category = @"File Name Scan", Label = @"IDA disassembler detected", Severity = Severity.Medium, Confidence = 70, Score = 24 },
                new FileNameRule { Token = @"hex rays", Category = @"File Name Scan", Label = @"Hex-Rays decompiler detected", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"hexrays", Category = @"File Name Scan", Label = @"Hex-Rays decompiler detected", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"ghidra", Category = @"File Name Scan", Label = @"Ghidra reverse-engineering suite detected", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"binary ninja", Category = @"File Name Scan", Label = @"Binary Ninja disassembler detected", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"binaryninja", Category = @"File Name Scan", Label = @"Binary Ninja disassembler detected", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"radare2", Category = @"File Name Scan", Label = @"Radare2 reverse-engineering tool detected", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"cutter", Category = @"File Name Scan", Label = @"Cutter reverse-engineering tool detected", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"dnspy", Category = @"File Name Scan", Label = @".NET game decompilation tool detected", Severity = Severity.Medium, Confidence = 68, Score = 22 },
                new FileNameRule { Token = @"ilspy", Category = @"File Name Scan", Label = @".NET game decompilation tool detected", Severity = Severity.Medium, Confidence = 68, Score = 22 },
                new FileNameRule { Token = @"de4dot", Category = @"File Name Scan", Label = @".NET deobfuscation tool detected", Severity = Severity.Medium, Confidence = 68, Score = 22 },
                new FileNameRule { Token = @"reclass", Category = @"File Name Scan", Label = @"Memory/reversing tool detected", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"scylla", Category = @"File Name Scan", Label = @"Dumping/reversing tool detected", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"system informer", Category = @"File Name Scan", Label = @"System Informer process inspection tool detected", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"systeminformer", Category = @"File Name Scan", Label = @"System Informer process inspection tool detected", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"process hacker", Category = @"File Name Scan", Label = @"Process Hacker inspection tool detected", Severity = Severity.Medium, Confidence = 62, Score = 18 },
                new FileNameRule { Token = @"processhacker", Category = @"File Name Scan", Label = @"Process Hacker inspection tool detected", Severity = Severity.Medium, Confidence = 62, Score = 18 },
                new FileNameRule { Token = @"procexp", Category = @"File Name Scan", Label = @"Process Explorer detected", Severity = Severity.Low, Confidence = 45, Score = 6 },
            };

            AddExtendedFileNameRules(rules);
            return rules;
        }

        public static List<FileNameRule> InstalledProgramRules()
        {
            var rules = new List<FileNameRule>
            {
                new FileNameRule { Token = @"cheat engine", Category = @"Installed Programs", Label = @"Cheat Engine memory editor installed", Severity = Severity.High, Confidence = 84, Score = 45 },
                new FileNameRule { Token = @"cheatengine", Category = @"Installed Programs", Label = @"Cheat Engine memory editor installed", Severity = Severity.High, Confidence = 84, Score = 45 },
                new FileNameRule { Token = @"wemod", Category = @"Installed Programs", Label = @"WeMod game trainer installed", Severity = Severity.High, Confidence = 80, Score = 38 },
                new FileNameRule { Token = @"ida", Category = @"Installed Programs", Label = @"IDA disassembler installed", Severity = Severity.Low, Confidence = 62, Score = 10 },
                new FileNameRule { Token = @"ida pro", Category = @"Installed Programs", Label = @"IDA disassembler installed", Severity = Severity.Low, Confidence = 64, Score = 12 },
                new FileNameRule { Token = @"ida64", Category = @"Installed Programs", Label = @"IDA disassembler installed", Severity = Severity.Low, Confidence = 62, Score = 10 },
                new FileNameRule { Token = @"hex rays", Category = @"Installed Programs", Label = @"Hex-Rays decompiler installed", Severity = Severity.Low, Confidence = 62, Score = 10 },
                new FileNameRule { Token = @"hexrays", Category = @"Installed Programs", Label = @"Hex-Rays decompiler installed", Severity = Severity.Low, Confidence = 62, Score = 10 },
                new FileNameRule { Token = @"ghidra", Category = @"Installed Programs", Label = @"Ghidra reverse-engineering suite installed", Severity = Severity.Low, Confidence = 62, Score = 10 },
                new FileNameRule { Token = @"binary ninja", Category = @"Installed Programs", Label = @"Binary Ninja disassembler installed", Severity = Severity.Low, Confidence = 62, Score = 10 },
                new FileNameRule { Token = @"binaryninja", Category = @"Installed Programs", Label = @"Binary Ninja disassembler installed", Severity = Severity.Low, Confidence = 62, Score = 10 },
                new FileNameRule { Token = @"x64dbg", Category = @"Installed Programs", Label = @"Game debugging/disassembly tool installed", Severity = Severity.Low, Confidence = 60, Score = 8 },
                new FileNameRule { Token = @"x32dbg", Category = @"Installed Programs", Label = @"Game debugging/disassembly tool installed", Severity = Severity.Low, Confidence = 60, Score = 8 },
                new FileNameRule { Token = @"ollydbg", Category = @"Installed Programs", Label = @"Game debugging/disassembly tool installed", Severity = Severity.Low, Confidence = 60, Score = 8 },
                new FileNameRule { Token = @"dnspy", Category = @"Installed Programs", Label = @".NET decompilation tool installed", Severity = Severity.Low, Confidence = 60, Score = 8 },
                new FileNameRule { Token = @"ilspy", Category = @"Installed Programs", Label = @".NET decompilation tool installed", Severity = Severity.Low, Confidence = 60, Score = 8 },
                new FileNameRule { Token = @"de4dot", Category = @"Installed Programs", Label = @".NET deobfuscation tool installed", Severity = Severity.Low, Confidence = 58, Score = 6 },
                new FileNameRule { Token = @"reclass", Category = @"Installed Programs", Label = @"Memory/reversing tool installed", Severity = Severity.Low, Confidence = 58, Score = 6 },
                new FileNameRule { Token = @"scylla", Category = @"Installed Programs", Label = @"Dumping/reversing tool installed", Severity = Severity.Low, Confidence = 58, Score = 6 },
                new FileNameRule { Token = @"system informer", Category = @"Installed Programs", Label = @"System Informer process inspection tool installed", Severity = Severity.Low, Confidence = 55, Score = 5 },
                new FileNameRule { Token = @"systeminformer", Category = @"Installed Programs", Label = @"System Informer process inspection tool installed", Severity = Severity.Low, Confidence = 55, Score = 5 },
                new FileNameRule { Token = @"process hacker", Category = @"Installed Programs", Label = @"Process Hacker inspection tool installed", Severity = Severity.Low, Confidence = 55, Score = 5 },
                new FileNameRule { Token = @"processhacker", Category = @"Installed Programs", Label = @"Process Hacker inspection tool installed", Severity = Severity.Low, Confidence = 55, Score = 5 },
            };

            AddExtendedInstalledProgramRules(rules);
            return rules;
        }

        public static List<FileNameRule> BrowserHistoryRules()
        {
            var rules = new List<FileNameRule>
            {
                new FileNameRule { Token = @"unknowncheats", Category = @"Browser History", Label = @"Browser history shows known cheat forum/site", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"unknowncheats.me", Category = @"Browser History", Label = @"Browser history shows known cheat forum/site", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"guidedhacking", Category = @"Browser History", Label = @"Browser history shows game-hacking forum/site", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"guidedhacking.com", Category = @"Browser History", Label = @"Browser history shows game-hacking forum/site", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"elitepvpers.com", Category = @"Browser History", Label = @"Browser history shows cheat marketplace/forum domain", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"blackhatworld.com", Category = @"Browser History", Label = @"Browser history shows blackhat marketplace/forum domain", Severity = Severity.Medium, Confidence = 68, Score = 24 },
                new FileNameRule { Token = @"lethality.club", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"evicted.wtf", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"cheatprovider.store", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"burgercheats.com", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"team073.com", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"spyderrz.com", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"not-reversing.com", Category = @"Browser History", Label = @"Browser history shows reversing/cheat tooling domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"beaztcheats.com", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"suspectcheats.com", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"lexshop.xyz", Category = @"Browser History", Label = @"Browser history shows cheat/service shop domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"shxdowcheats.net", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"ssz.gg", Category = @"Browser History", Label = @"Browser history shows cheat/service domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"apexdma.xyz", Category = @"Browser History", Label = @"Browser history shows DMA cheat/service domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"sapphire-service.shop", Category = @"Browser History", Label = @"Browser history shows cheat/service shop domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"only-cheats.com", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"deprimereshop.com", Category = @"Browser History", Label = @"Browser history shows cheat/service shop domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"kernaim.to", Category = @"Browser History", Label = @"Browser history shows kernel/aim cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"cosmocheats.com", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"disconnect.wtf", Category = @"Browser History", Label = @"Browser history shows cheat/service domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"disconnectcheats.com", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"mpgh.net", Category = @"Browser History", Label = @"Browser history shows game-hacking forum/site", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"aimjunkies.com", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"artificialaiming.net", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"klar.gg", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"phantomoverlay.io", Category = @"Browser History", Label = @"Browser history shows cheat provider domain", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"cheats.com", Category = @"Browser History", Label = @"Browser history shows cheat-related domain wording", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"cheats.net", Category = @"Browser History", Label = @"Browser history shows cheat-related domain wording", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"cheats.gg", Category = @"Browser History", Label = @"Browser history shows cheat-related domain wording", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"cheats.xyz", Category = @"Browser History", Label = @"Browser history shows cheat-related domain wording", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"cheat.shop", Category = @"Browser History", Label = @"Browser history shows cheat-related shop domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"cheat.store", Category = @"Browser History", Label = @"Browser history shows cheat-related shop domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"aimbot", Category = @"Browser History", Label = @"Browser history shows cheat feature keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"triggerbot", Category = @"Browser History", Label = @"Browser history shows cheat feature keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"wallhack", Category = @"Browser History", Label = @"Browser history shows cheat feature keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"ragebot", Category = @"Browser History", Label = @"Browser history shows cheat feature keyword", Severity = Severity.High, Confidence = 76, Score = 35 },
                new FileNameRule { Token = @"silent aim", Category = @"Browser History", Label = @"Browser history shows cheat feature keyword", Severity = Severity.High, Confidence = 75, Score = 35 },
                new FileNameRule { Token = @"cs2 cheat", Category = @"Browser History", Label = @"Browser history shows game cheat keyword", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"csgo cheat", Category = @"Browser History", Label = @"Browser history shows game cheat keyword", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"valorant cheat", Category = @"Browser History", Label = @"Browser history shows game cheat keyword", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"fortnite cheat", Category = @"Browser History", Label = @"Browser history shows game cheat keyword", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"warzone cheat", Category = @"Browser History", Label = @"Browser history shows game cheat keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"apex cheat", Category = @"Browser History", Label = @"Browser history shows game cheat keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"dma cheat", Category = @"Browser History", Label = @"Browser history shows DMA cheat keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"kdmapper", Category = @"Browser History", Label = @"Browser history shows kernel driver mapper keyword", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"driver mapper", Category = @"Browser History", Label = @"Browser history shows kernel driver mapper keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"manual map", Category = @"Browser History", Label = @"Browser history shows manual mapping keyword", Severity = Severity.Medium, Confidence = 65, Score = 22 },
                new FileNameRule { Token = @"eac bypass", Category = @"Browser History", Label = @"Browser history shows anti-cheat bypass keyword", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"battleye bypass", Category = @"Browser History", Label = @"Browser history shows anti-cheat bypass keyword", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"vanguard bypass", Category = @"Browser History", Label = @"Browser history shows anti-cheat bypass keyword", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"hwid spoofer", Category = @"Browser History", Label = @"Browser history shows hardware ID spoofer keyword", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"trace cleaner", Category = @"Browser History", Label = @"Browser history shows trace-cleaner keyword", Severity = Severity.Medium, Confidence = 70, Score = 25 },
                new FileNameRule { Token = @"extreme injector", Category = @"Browser History", Label = @"Browser history shows injector keyword", Severity = Severity.Medium, Confidence = 70, Score = 25 },
                new FileNameRule { Token = @"injector", Category = @"Browser History", Label = @"Browser history shows injector keyword", Severity = Severity.Medium, Confidence = 60, Score = 18 },
                new FileNameRule { Token = @"cheat engine", Category = @"Browser History", Label = @"Browser history shows Cheat Engine / memory editor keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"cheatengine", Category = @"Browser History", Label = @"Browser history shows Cheat Engine / memory editor keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"wemod", Category = @"Browser History", Label = @"Browser history shows WeMod game trainer keyword", Severity = Severity.High, Confidence = 76, Score = 35 },
                new FileNameRule { Token = @"ida pro", Category = @"Browser History", Label = @"Browser history shows IDA disassembler keyword", Severity = Severity.Medium, Confidence = 70, Score = 25 },
                new FileNameRule { Token = @"ida64", Category = @"Browser History", Label = @"Browser history shows IDA disassembler keyword", Severity = Severity.Medium, Confidence = 68, Score = 22 },
                new FileNameRule { Token = @"ghidra", Category = @"Browser History", Label = @"Browser history shows Ghidra reverse-engineering keyword", Severity = Severity.Medium, Confidence = 68, Score = 22 },
                new FileNameRule { Token = @"binary ninja", Category = @"Browser History", Label = @"Browser history shows Binary Ninja disassembler keyword", Severity = Severity.Medium, Confidence = 68, Score = 22 },
                new FileNameRule { Token = @"x64dbg", Category = @"Browser History", Label = @"Browser history shows debugger/disassembler keyword", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"dnspy", Category = @"Browser History", Label = @"Browser history shows .NET decompiler keyword", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"ilspy", Category = @"Browser History", Label = @"Browser history shows .NET decompiler keyword", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"system informer", Category = @"Browser History", Label = @"Browser history shows process inspection keyword", Severity = Severity.Medium, Confidence = 62, Score = 18 },
                new FileNameRule { Token = @"process hacker", Category = @"Browser History", Label = @"Browser history shows process inspection keyword", Severity = Severity.Medium, Confidence = 62, Score = 18 },
                new FileNameRule { Token = @"kmbox", Category = @"Browser History", Label = @"Browser history shows external input-assist tooling keyword", Severity = Severity.Medium, Confidence = 70, Score = 25 },
            };

            AddExtendedBrowserHistoryRules(rules);
            return rules;
        }

        public static List<FileNameRule> ExecutionRules()
        {
            var rules = new List<FileNameRule>
            {
                new FileNameRule { Token = @"kdmapper", Category = @"Execution Evidence", Label = @"Kernel driver mapper execution trace", Severity = Severity.High, Confidence = 86, Score = 55 },
                new FileNameRule { Token = @"driver mapper", Category = @"Execution Evidence", Label = @"Kernel driver mapper execution trace", Severity = Severity.High, Confidence = 82, Score = 48 },
                new FileNameRule { Token = @"manual map", Category = @"Execution Evidence", Label = @"Manual-mapping execution trace", Severity = Severity.High, Confidence = 78, Score = 42 },
                new FileNameRule { Token = @"cheat engine", Category = @"Execution Evidence", Label = @"Cheat Engine execution trace", Severity = Severity.High, Confidence = 84, Score = 50 },
                new FileNameRule { Token = @"cheatengine", Category = @"Execution Evidence", Label = @"Cheat Engine execution trace", Severity = Severity.High, Confidence = 84, Score = 50 },
                new FileNameRule { Token = @"extreme injector", Category = @"Execution Evidence", Label = @"Extreme Injector execution trace", Severity = Severity.High, Confidence = 84, Score = 50 },
                new FileNameRule { Token = @"injector", Category = @"Execution Evidence", Label = @"Injector execution trace", Severity = Severity.Medium, Confidence = 68, Score = 30 },
                new FileNameRule { Token = @"wemod", Category = @"Execution Evidence", Label = @"WeMod/trainer execution trace", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"ida64", Category = @"Execution Evidence", Label = @"IDA disassembler execution trace", Severity = Severity.Medium, Confidence = 74, Score = 32 },
                new FileNameRule { Token = @"ida", Category = @"Execution Evidence", Label = @"IDA disassembler execution trace", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"hex rays", Category = @"Execution Evidence", Label = @"Hex-Rays decompiler execution trace", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"ghidra", Category = @"Execution Evidence", Label = @"Ghidra reverse-engineering execution trace", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"binary ninja", Category = @"Execution Evidence", Label = @"Binary Ninja execution trace", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"x64dbg", Category = @"Execution Evidence", Label = @"x64dbg debugger execution trace", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"x32dbg", Category = @"Execution Evidence", Label = @"x32dbg debugger execution trace", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"ollydbg", Category = @"Execution Evidence", Label = @"OllyDbg debugger execution trace", Severity = Severity.Medium, Confidence = 70, Score = 26 },
                new FileNameRule { Token = @"dnspy", Category = @"Execution Evidence", Label = @"dnSpy decompiler execution trace", Severity = Severity.Medium, Confidence = 70, Score = 26 },
                new FileNameRule { Token = @"ilspy", Category = @"Execution Evidence", Label = @"ILSpy decompiler execution trace", Severity = Severity.Medium, Confidence = 68, Score = 24 },
                new FileNameRule { Token = @"reclass", Category = @"Execution Evidence", Label = @"ReClass memory/reversing execution trace", Severity = Severity.Medium, Confidence = 68, Score = 24 },
                new FileNameRule { Token = @"system informer", Category = @"Execution Evidence", Label = @"System Informer process-inspection execution trace", Severity = Severity.Medium, Confidence = 66, Score = 22 },
                new FileNameRule { Token = @"process hacker", Category = @"Execution Evidence", Label = @"Process Hacker process-inspection execution trace", Severity = Severity.Medium, Confidence = 64, Score = 20 },
                new FileNameRule { Token = @"hwid spoofer", Category = @"Execution Evidence", Label = @"HWID spoofer execution trace", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"spoofer", Category = @"Execution Evidence", Label = @"Spoofer execution trace", Severity = Severity.Medium, Confidence = 66, Score = 26 },
                new FileNameRule { Token = @"trace cleaner", Category = @"Execution Evidence", Label = @"Trace-cleaner execution trace", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"aimbot", Category = @"Execution Evidence", Label = @"Cheat feature execution trace", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"triggerbot", Category = @"Execution Evidence", Label = @"Cheat feature execution trace", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"ragebot", Category = @"Execution Evidence", Label = @"Cheat feature execution trace", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"silent aim", Category = @"Execution Evidence", Label = @"Cheat feature execution trace", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"wallhack", Category = @"Execution Evidence", Label = @"Cheat feature execution trace", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"bypass", Category = @"Execution Evidence", Label = @"Anti-cheat bypass execution trace", Severity = Severity.Medium, Confidence = 66, Score = 28 },
            };

            AddExtendedExecutionRules(rules);
            return rules;
        }

        public static List<FileNameRule> BrowserDownloadRules()
        {
            var rules = new List<FileNameRule>
            {
                new FileNameRule { Token = @"unknowncheats", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows known cheat forum/site", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"unknowncheats.me", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows known cheat forum/site", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"guidedhacking", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows game-hacking forum/site", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"guidedhacking.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows game-hacking forum/site", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"elitepvpers.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat marketplace/forum domain", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"blackhatworld.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows blackhat marketplace/forum domain", Severity = Severity.Medium, Confidence = 68, Score = 24 },
                new FileNameRule { Token = @"lethality.club", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"evicted.wtf", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"cheatprovider.store", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"burgercheats.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"team073.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"spyderrz.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"not-reversing.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows reversing/cheat tooling domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"beaztcheats.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"suspectcheats.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"lexshop.xyz", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat/service shop domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"shxdowcheats.net", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"ssz.gg", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat/service domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"apexdma.xyz", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows DMA cheat/service domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"sapphire-service.shop", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat/service shop domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"only-cheats.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"deprimereshop.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat/service shop domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"kernaim.to", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows kernel/aim cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"cosmocheats.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"disconnect.wtf", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat/service domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"disconnectcheats.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 84, Score = 48 },
                new FileNameRule { Token = @"mpgh.net", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows game-hacking forum/site", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"aimjunkies.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"artificialaiming.net", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"klar.gg", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"phantomoverlay.io", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat provider domain", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"cheats.com", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat-related domain wording", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"cheats.net", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat-related domain wording", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"cheats.gg", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat-related domain wording", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"cheats.xyz", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat-related domain wording", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"cheat.shop", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat-related shop domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"cheat.store", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat-related shop domain", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"aimbot", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat feature keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"triggerbot", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat feature keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"wallhack", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat feature keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"ragebot", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat feature keyword", Severity = Severity.High, Confidence = 76, Score = 35 },
                new FileNameRule { Token = @"silent aim", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows cheat feature keyword", Severity = Severity.High, Confidence = 75, Score = 35 },
                new FileNameRule { Token = @"cs2 cheat", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows game cheat keyword", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"csgo cheat", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows game cheat keyword", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"valorant cheat", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows game cheat keyword", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"fortnite cheat", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows game cheat keyword", Severity = Severity.High, Confidence = 80, Score = 42 },
                new FileNameRule { Token = @"warzone cheat", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows game cheat keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"apex cheat", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows game cheat keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"dma cheat", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows DMA cheat keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"kdmapper", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows kernel driver mapper keyword", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"driver mapper", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows kernel driver mapper keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"manual map", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows manual mapping keyword", Severity = Severity.Medium, Confidence = 65, Score = 22 },
                new FileNameRule { Token = @"eac bypass", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows anti-cheat bypass keyword", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"battleye bypass", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows anti-cheat bypass keyword", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"vanguard bypass", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows anti-cheat bypass keyword", Severity = Severity.High, Confidence = 82, Score = 45 },
                new FileNameRule { Token = @"hwid spoofer", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows hardware ID spoofer keyword", Severity = Severity.Medium, Confidence = 72, Score = 28 },
                new FileNameRule { Token = @"trace cleaner", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows trace-cleaner keyword", Severity = Severity.Medium, Confidence = 70, Score = 25 },
                new FileNameRule { Token = @"extreme injector", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows injector keyword", Severity = Severity.Medium, Confidence = 70, Score = 25 },
                new FileNameRule { Token = @"injector", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows injector keyword", Severity = Severity.Medium, Confidence = 60, Score = 18 },
                new FileNameRule { Token = @"cheat engine", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows Cheat Engine / memory editor keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"cheatengine", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows Cheat Engine / memory editor keyword", Severity = Severity.High, Confidence = 78, Score = 38 },
                new FileNameRule { Token = @"wemod", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows WeMod game trainer keyword", Severity = Severity.High, Confidence = 76, Score = 35 },
                new FileNameRule { Token = @"ida pro", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows IDA disassembler keyword", Severity = Severity.Medium, Confidence = 70, Score = 25 },
                new FileNameRule { Token = @"ida64", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows IDA disassembler keyword", Severity = Severity.Medium, Confidence = 68, Score = 22 },
                new FileNameRule { Token = @"ghidra", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows Ghidra reverse-engineering keyword", Severity = Severity.Medium, Confidence = 68, Score = 22 },
                new FileNameRule { Token = @"binary ninja", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows Binary Ninja disassembler keyword", Severity = Severity.Medium, Confidence = 68, Score = 22 },
                new FileNameRule { Token = @"x64dbg", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows debugger/disassembler keyword", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"dnspy", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows .NET decompiler keyword", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"ilspy", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows .NET decompiler keyword", Severity = Severity.Medium, Confidence = 65, Score = 20 },
                new FileNameRule { Token = @"system informer", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows process inspection keyword", Severity = Severity.Medium, Confidence = 62, Score = 18 },
                new FileNameRule { Token = @"process hacker", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows process inspection keyword", Severity = Severity.Medium, Confidence = 62, Score = 18 },
                new FileNameRule { Token = @"kmbox", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record shows external input-assist tooling keyword", Severity = Severity.Medium, Confidence = 70, Score = 25 },
                new FileNameRule { Token = @"loader", Category = @"Browser Source/Download Evidence", Label = @"Browser source/download record for loader/tooling", Severity = Severity.Medium, Confidence = 62, Score = 22 },
            };

            AddExtendedBrowserDownloadRules(rules);
            return rules;
        }



        private static void AddExtendedFileNameRules(List<FileNameRule> rules)
        {
            AddRules(rules, "File Name Scan", "Cheat feature / file name term detected", Severity.High, 78, 38,
                @"aimbot", @"aim bot", @"aim-assist", @"aim assist", @"aimlock", @"aim lock", @"silent aim", @"silentaim",
                @"triggerbot", @"trigger bot", @"autofire", @"auto fire", @"rapid fire", @"ragebot", @"rage bot", @"legitbot", @"legit bot",
                @"wallhack", @"wall hack", @"esp hack", @"player esp", @"loot esp", @"item esp", @"radar hack", @"radarhack",
                @"chams", @"glow esp", @"snaplines", @"snap lines", @"skeleton esp", @"box esp", @"health esp", @"name esp", @"distance esp",
                @"spinbot", @"spin bot", @"anti aim", @"antiaim", @"resolver", @"backtrack", @"fake lag", @"fakelag",
                @"norecoil", @"no recoil", @"recoil script", @"recoil macro", @"rcs script", @"bunnyhop", @"bunny hop", @"bhop",
                @"speedhack", @"speed hack", @"flyhack", @"fly hack", @"noclip", @"no clip", @"magic bullet", @"bullet teleport",
                @"skin changer", @"skinchanger", @"unlock all", @"unlocker", @"soft unlock", @"softunlock");

            AddRules(rules, "File Name Scan", "Cheat project / build wording detected", Severity.High, 82, 45,
                @"cheat source", @"cheat src", @"cheat project", @"cheat build", @"cheat base", @"cheat framework", @"cheat sdk", @"hack source", @"hack src",
                @"external cheat", @"internal cheat", @"external base", @"internal base", @"external overlay", @"internal dll", @"cheat dll", @"cheat loader",
                @"game hack", @"game hacking", @"undetected cheat", @"private cheat", @"p2c", @"pay to cheat", @"paste cheat", @"cheat paste", @"cracked cheat");

            AddRules(rules, "File Name Scan", "Injector / mapper / kernel tooling detected", Severity.High, 82, 45,
                @"dll injector", @"injector", @"injection", @"loadlibrary injector", @"manual mapper", @"manualmap", @"manual map", @"reflective loader",
                @"kernel mapper", @"driver mapper", @"kdmapper", @"kdu", @"drvmap", @"iqvw64e", @"capcom driver", @"vulnerable driver",
                @"dse bypass", @"driver bypass", @"kernel bypass", @"kernelmode cheat", @"kernel mode cheat", @"ring0 cheat", @"ring 0 cheat");

            AddRules(rules, "File Name Scan", "Anti-cheat bypass / cleaner wording detected", Severity.High, 80, 42,
                @"eac bypass", @"easy anti cheat bypass", @"easyanticheat bypass", @"battleye bypass", @"be bypass", @"battl eye bypass",
                @"vanguard bypass", @"vgk bypass", @"vgc bypass", @"faceit bypass", @"esea bypass", @"ricochet bypass", @"anti cheat bypass", @"anticheat bypass",
                @"hwid spoofer", @"hwid spoof", @"hwid bypass", @"hwid reset", @"hwid changer", @"serial spoofer", @"serial changer", @"unban tool", @"trace cleaner", @"pc cleaner", @"temp cleaner");

            AddRules(rules, "File Name Scan", "DMA / external input-assist wording detected", Severity.High, 78, 38,
                @"dma cheat", @"dma radar", @"dma firmware", @"pcileech", @"memprocfs", @"leechcore", @"screamer pci", @"pcie squirrel", @"dma board", @"fuser",
                @"kmbox", @"km box", @"kmbox net", @"kmbox b", @"arduino aimbot", @"arduino colorbot", @"colorbot", @"color bot", @"pixelbot", @"pixel bot", @"hid spoof", @"mouse aimbot");

            AddKnownCheatBrandRules(rules, "File Name Scan", "Known cheat brand / project term detected", Severity.Medium, 72, 28);
            AddGameSpecificCheatRules(rules, "File Name Scan", "Game-specific cheat wording detected", Severity.High, 78, 38);
            AddCheatFeatureExpansionRules(rules, "File Name Scan", "Cheat feature / config term detected", Severity.High, 78, 38);
            AddCheatBuildAndSourceExpansionRules(rules, "File Name Scan", "Cheat source / build / SDK term detected", Severity.High, 82, 45);
            AddInjectorKernelDriverExpansionRules(rules, "File Name Scan", "Injector / mapper / driver tooling term detected", Severity.High, 82, 45);
            AddSpooferCleanerExpansionRules(rules, "File Name Scan", "Spoofer / cleaner / unban term detected", Severity.High, 80, 42);
            AddExternalHardwareAssistExpansionRules(rules, "File Name Scan", "External hardware / input-assist term detected", Severity.High, 78, 38);
            AddProviderAndProjectExpansionRules(rules, "File Name Scan", "Known cheat provider / project term detected", Severity.Medium, 72, 28);
            AddLoaderExpansionRules(rules, "File Name Scan", "Cheat loader / distribution term detected", Severity.High, 82, 45, true);
            AddGameSpecificExpansionRules(rules, "File Name Scan", "Game-specific cheat term detected", Severity.High, 78, 38);
            AddShortAcronymFileNameRules(rules, "File Name Scan", "Short cheat acronym / feature filename detected", Severity.Medium, 68, 22);
            AddSingleWordCheatTermRules(rules, "File Name Scan", "Possible cheat-related filename term", Severity.Medium, 66, 20, true);
            AddCheatSourceFileNameRules(rules, "File Name Scan", "Cheat source filename / module detected", Severity.High, 82, 45);
        }

        private static void AddExtendedInstalledProgramRules(List<FileNameRule> rules)
        {
            AddRules(rules, "Installed Programs", "Installed game trainer / cheat tool detected", Severity.High, 78, 35,
                @"cheat engine", @"cheatengine", @"wemod", @"artmoney", @"cosmos", @"game trainer", @"trainer manager", @"plitch");

            AddRules(rules, "Installed Programs", "Installed reversing / debugging tool detected", Severity.Low, 58, 8,
                @"x64dbg", @"x32dbg", @"ollydbg", @"ida", @"ida pro", @"ghidra", @"binary ninja", @"dnspy", @"ilspy", @"reclass", @"scylla", @"process hacker", @"system informer", @"pe-bear", @"hxd");

            AddInstalledProgramExpansionRules(rules, "Installed Programs", "Installed cheat / trainer / reversing tool detected", Severity.Medium, 68, 18);
            AddLoaderExpansionRules(rules, "Installed Programs", "Installed cheat loader / distribution tool detected", Severity.High, 76, 32, false);
            AddSingleWordCheatTermRules(rules, "Installed Programs", "Possible tool keyword in installed app", Severity.Low, 54, 8, false);
        }

        private static void AddExtendedBrowserHistoryRules(List<FileNameRule> rules)
        {
            AddRules(rules, "Browser History", "Browser history shows cheat feature keyword", Severity.High, 78, 38,
                @"aimbot", @"aim bot", @"aim-assist", @"aim assist", @"aimlock", @"silent aim", @"triggerbot", @"trigger bot", @"wallhack", @"wall hack",
                @"esp cheat", @"player esp", @"loot esp", @"radar hack", @"chams", @"glow esp", @"ragebot", @"legitbot", @"spinbot", @"anti aim", @"no recoil", @"recoil script", @"bunnyhop", @"bhop", @"skin changer", @"unlock all");

            AddRules(rules, "Browser History", "Browser history shows bypass / spoofing keyword", Severity.High, 80, 42,
                @"eac bypass", @"easy anti cheat bypass", @"battleye bypass", @"be bypass", @"vanguard bypass", @"vgk bypass", @"vgc bypass", @"faceit bypass", @"ricochet bypass", @"hwid spoofer", @"hwid spoof", @"unban tool", @"trace cleaner");

            AddRules(rules, "Browser History", "Browser history shows injector / mapper keyword", Severity.High, 80, 42,
                @"dll injector", @"extreme injector", @"manual mapper", @"manual map", @"kdmapper", @"driver mapper", @"kernel mapper", @"vulnerable driver", @"dse bypass");

            AddRules(rules, "Browser History", "Browser history shows DMA / external input-assist keyword", Severity.High, 76, 35,
                @"dma cheat", @"dma radar", @"dma firmware", @"pcileech", @"memprocfs", @"leechcore", @"screamer pci", @"pcie squirrel", @"kmbox", @"km box", @"arduino aimbot", @"colorbot", @"pixelbot");

            AddKnownCheatBrandRules(rules, "Browser History", "Browser history shows known cheat brand / project term", Severity.High, 78, 38);
            AddGameSpecificCheatRules(rules, "Browser History", "Browser history shows game-specific cheat wording", Severity.High, 78, 38);
            AddCheatDomainRules(rules, "Browser History", "Browser history shows cheat forum / provider domain", Severity.High, 80, 42);
            AddCheatFeatureExpansionRules(rules, "Browser History", "Browser history shows cheat feature / config term", Severity.High, 78, 38);
            AddCheatBuildAndSourceExpansionRules(rules, "Browser History", "Browser history shows cheat source / build / SDK term", Severity.High, 80, 42);
            AddInjectorKernelDriverExpansionRules(rules, "Browser History", "Browser history shows injector / mapper / driver term", Severity.High, 80, 42);
            AddSpooferCleanerExpansionRules(rules, "Browser History", "Browser history shows spoofer / cleaner / unban term", Severity.High, 80, 42);
            AddExternalHardwareAssistExpansionRules(rules, "Browser History", "Browser history shows hardware / input-assist cheat term", Severity.High, 76, 35);
            AddProviderAndProjectExpansionRules(rules, "Browser History", "Browser history shows known cheat provider / project term", Severity.High, 78, 38);
            AddLoaderExpansionRules(rules, "Browser History", "Browser history shows cheat loader / distribution term", Severity.High, 78, 38, false);
            AddGameSpecificExpansionRules(rules, "Browser History", "Browser history shows game-specific cheat term", Severity.High, 78, 38);
            AddSingleWordCheatTermRules(rules, "Browser History", "Possible cheat-related browser term", Severity.Medium, 60, 15, false);
        }

        private static void AddExtendedExecutionRules(List<FileNameRule> rules)
        {
            AddRules(rules, "Execution Evidence", "Cheat tool / project execution trace", Severity.High, 84, 50,
                @"aimbot", @"triggerbot", @"wallhack", @"esp", @"ragebot", @"legitbot", @"cheat loader", @"cheatengine", @"cheat engine", @"wemod", @"artmoney", @"game trainer");

            AddRules(rules, "Execution Evidence", "Injector / mapper execution trace", Severity.High, 84, 50,
                @"dll injector", @"extreme injector", @"manual mapper", @"manualmap", @"kdmapper", @"driver mapper", @"kernel mapper", @"kdu", @"drvmap", @"iqvw64e", @"capcom driver");

            AddRules(rules, "Execution Evidence", "Bypass / spoofer / cleaner execution trace", Severity.High, 80, 42,
                @"eac bypass", @"battleye bypass", @"vanguard bypass", @"faceit bypass", @"hwid spoofer", @"hwid spoof", @"serial changer", @"unban tool", @"trace cleaner");

            AddRules(rules, "Execution Evidence", "DMA / input-assist execution trace", Severity.High, 78, 38,
                @"dma radar", @"pcileech", @"memprocfs", @"leechcore", @"kmbox", @"km box", @"colorbot", @"pixelbot", @"arduino aimbot");

            AddKnownCheatBrandRules(rules, "Execution Evidence", "Known cheat brand / project execution trace", Severity.High, 78, 38);
            AddCheatFeatureExpansionRules(rules, "Execution Evidence", "Cheat feature / config execution trace", Severity.High, 82, 45);
            AddCheatBuildAndSourceExpansionRules(rules, "Execution Evidence", "Cheat source / build tooling execution trace", Severity.High, 82, 45);
            AddInjectorKernelDriverExpansionRules(rules, "Execution Evidence", "Injector / mapper / driver tooling execution trace", Severity.High, 84, 50);
            AddSpooferCleanerExpansionRules(rules, "Execution Evidence", "Spoofer / cleaner / unban execution trace", Severity.High, 82, 45);
            AddExternalHardwareAssistExpansionRules(rules, "Execution Evidence", "Hardware / input-assist execution trace", Severity.High, 78, 38);
            AddProviderAndProjectExpansionRules(rules, "Execution Evidence", "Known cheat provider / project execution trace", Severity.High, 78, 38);
            AddLoaderExpansionRules(rules, "Execution Evidence", "Cheat loader / distribution execution trace", Severity.High, 84, 50, true);
            AddGameSpecificExpansionRules(rules, "Execution Evidence", "Game-specific cheat execution trace", Severity.High, 78, 38);
            AddSingleWordCheatTermRules(rules, "Execution Evidence", "Possible cheat/tool launch term", Severity.Medium, 68, 24, true);
        }

        private static void AddExtendedBrowserDownloadRules(List<FileNameRule> rules)
        {
            AddRules(rules, "Browser Source/Download Evidence", "Browser source/download shows cheat feature keyword", Severity.High, 78, 38,
                @"aimbot", @"aim bot", @"aim-assist", @"aim assist", @"silent aim", @"triggerbot", @"trigger bot", @"wallhack", @"wall hack", @"esp cheat", @"player esp", @"loot esp", @"radar hack", @"chams", @"glow esp", @"ragebot", @"legitbot", @"no recoil", @"recoil script", @"bunnyhop", @"bhop", @"skin changer", @"unlock all");

            AddRules(rules, "Browser Source/Download Evidence", "Browser source/download shows bypass / spoofing keyword", Severity.High, 80, 42,
                @"eac bypass", @"easy anti cheat bypass", @"battleye bypass", @"be bypass", @"vanguard bypass", @"vgk bypass", @"faceit bypass", @"ricochet bypass", @"hwid spoofer", @"hwid spoof", @"unban tool", @"trace cleaner");

            AddRules(rules, "Browser Source/Download Evidence", "Browser source/download shows injector / mapper keyword", Severity.High, 80, 42,
                @"dll injector", @"extreme injector", @"manual mapper", @"manual map", @"kdmapper", @"driver mapper", @"kernel mapper", @"vulnerable driver", @"dse bypass");

            AddRules(rules, "Browser Source/Download Evidence", "Browser source/download shows DMA / external input-assist keyword", Severity.High, 76, 35,
                @"dma cheat", @"dma radar", @"dma firmware", @"pcileech", @"memprocfs", @"leechcore", @"screamer pci", @"pcie squirrel", @"kmbox", @"km box", @"arduino aimbot", @"colorbot", @"pixelbot");

            AddKnownCheatBrandRules(rules, "Browser Source/Download Evidence", "Browser source/download shows known cheat brand / project term", Severity.High, 78, 38);
            AddGameSpecificCheatRules(rules, "Browser Source/Download Evidence", "Browser source/download shows game-specific cheat wording", Severity.High, 78, 38);
            AddCheatDomainRules(rules, "Browser Source/Download Evidence", "Browser source/download shows cheat forum / provider domain", Severity.High, 80, 42);
            AddCheatFeatureExpansionRules(rules, "Browser Source/Download Evidence", "Browser source/download shows cheat feature / config term", Severity.High, 78, 38);
            AddCheatBuildAndSourceExpansionRules(rules, "Browser Source/Download Evidence", "Browser source/download shows cheat source / build / SDK term", Severity.High, 80, 42);
            AddInjectorKernelDriverExpansionRules(rules, "Browser Source/Download Evidence", "Browser source/download shows injector / mapper / driver term", Severity.High, 80, 42);
            AddSpooferCleanerExpansionRules(rules, "Browser Source/Download Evidence", "Browser source/download shows spoofer / cleaner / unban term", Severity.High, 80, 42);
            AddExternalHardwareAssistExpansionRules(rules, "Browser Source/Download Evidence", "Browser source/download shows hardware / input-assist cheat term", Severity.High, 76, 35);
            AddProviderAndProjectExpansionRules(rules, "Browser Source/Download Evidence", "Browser source/download shows known cheat provider / project term", Severity.High, 78, 38);
            AddLoaderExpansionRules(rules, "Browser Source/Download Evidence", "Browser source/download shows cheat loader / distribution term", Severity.High, 80, 42, true);
            AddGameSpecificExpansionRules(rules, "Browser Source/Download Evidence", "Browser source/download shows game-specific cheat term", Severity.High, 78, 38);
            AddSingleWordCheatTermRules(rules, "Browser Source/Download Evidence", "Possible cheat-related download/source term", Severity.Medium, 62, 18, true);
        }

        private static void AddKnownCheatBrandRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"aimware", @"aimware.net", @"neverlose", @"neverlose.cc", @"gamesense", @"skeet", @"onetap", @"onetap.com", @"fatality", @"fatality.win",
                @"primordial", @"primordial.dev", @"interium", @"legendware", @"rifk7", @"pandora", @"nixware", @"memesense", @"plaguecheat", @"mutiny",
                @"ev0lve", @"ev0lve.xyz", @"iniuria", @"midnight", @"midnite", @"airflow", @"monolith", @"otc", @"otcv3", @"onetap crack", @"supremacy", @"sensum",
                @"osiris", @"nullhooks", @"aimtux", @"cathook", @"lmaobox", @"nullcore", @"rijin", @"vape v4", @"vape lite", @"drip lite", @"whiteout", @"entropy", @"dream advanced",
                @"meteor client", @"wurst client", @"impact client", @"liquidbounce", @"aristois", @"raven b+", @"sigma client", @"inertia client", @"future client", @"konas", @"rusherhack",
                @"pyro client", @"kami blue", @"lambda client", @"bleachhack", @"salhack", @"phobos", @"seppuku", @"moneymod", @"novoline", @"rise client",
                @"synapse x", @"krnl", @"jjsploit", @"scriptware", @"fluxus", @"solara executor", @"oxygen u", @"evon executor", @"delta executor", @"codex executor");
        }

        private static void AddGameSpecificCheatRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"cs2 cheat", @"cs2 external", @"cs2 internal", @"cs2 esp", @"cs2 aimbot", @"cs2 triggerbot", @"cs2 skinchanger", @"cs2 hvh",
                @"csgo cheat", @"csgo external", @"csgo internal", @"csgo esp", @"csgo aimbot", @"csgo hvh",
                @"valorant cheat", @"valorant triggerbot", @"valorant colorbot", @"valorant aimbot", @"valorant esp", @"valorant spoofer", @"vanguard spoofer",
                @"fortnite cheat", @"fortnite aimbot", @"fortnite softaim", @"fortnite esp", @"fortnite dma", @"fortnite spoofer", @"fortnite unlocker",
                @"apex cheat", @"apex aimbot", @"apex esp", @"apex dma", @"apex spoofer",
                @"warzone cheat", @"warzone aimbot", @"warzone esp", @"warzone unlocker", @"warzone spoofer", @"mw3 cheat", @"mw2 cheat", @"cod cheat", @"cod unlocker",
                @"rust cheat", @"rust esp", @"rust recoil", @"rust script", @"rust spoofer",
                @"tarkov cheat", @"eft cheat", @"eft esp", @"eft radar", @"eft dma",
                @"r6 cheat", @"rainbow six cheat", @"siege cheat", @"siege recoil", @"r6 recoil",
                @"fivem cheat", @"fivem executor", @"fivem lua", @"lua executor", @"gta cheat", @"gta mod menu",
                @"minecraft cheat", @"minecraft client", @"minecraft ghost client", @"minecraft autoclicker", @"autoclicker", @"auto clicker",
                @"roblox executor", @"roblox exploit", @"roblox cheat", @"roblox script executor");
        }

        private static void AddCheatDomainRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"unknowncheats", @"unknowncheats.me", @"guidedhacking", @"guidedhacking.com", @"elitepvpers", @"elitepvpers.com", @"mpgh", @"mpgh.net", @"yougame.biz",
                @"aimjunkies", @"aimjunkies.com", @"artificialaiming", @"artificialaiming.net", @"engineowning", @"engineowning.to", @"iwantcheats", @"iwantcheats.net", @"interwebz",
                @"systemcheats", @"ring-1", @"ring1", @"proofcore", @"klar.gg", @"phantomoverlay", @"phantomoverlay.io", @"kernaim", @"kernaim.to", @"securecheats", @"skycheats",
                @"x22cheats", @"x22", @"battlelog.co", @"cheater.fun", @"darkaim", @"cheatseller", @"cheat seller", @"cheat provider", @"cheat shop", @"cheat store",
                @"cheats.com", @"cheats.net", @"cheats.gg", @"cheats.xyz", @"cheat.shop", @"cheat.store");
        }


        private static void AddCheatFeatureExpansionRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"aimbot", @"aim bot", @"aimassist", @"aim assist", @"aim-assist", @"aimlock", @"aim lock", @"aim key", @"aimkey", @"aim smoothing", @"aim smooth", @"smoothing", @"fov circle", @"aim fov", @"fov changer",
                @"silent aim", @"silentaim", @"psilent", @"perfect silent", @"magic bullet", @"magicbullet", @"bullet tp", @"bullet teleport", @"projectile teleport", @"hitbox expander", @"hitbox extender", @"head prioritization",
                @"triggerbot", @"trigger bot", @"auto shoot", @"autoshoot", @"auto fire", @"autofire", @"rapidfire", @"rapid fire", @"quick stop", @"autostop", @"auto stop",
                @"ragebot", @"rage bot", @"legitbot", @"legit bot", @"semi rage", @"semirage", @"hvh", @"resolver", @"anti aim", @"antiaim", @"desync", @"fake angle", @"fake angles", @"fake duck", @"fakeduck", @"doubletap", @"double tap", @"hide shots", @"hideshots", @"lag exploit", @"tickbase", @"tickbase shift",
                @"esp cheat", @"esp hack", @"esp source", @"esp overlay", @"esp config", @"player esp", @"enemy esp", @"team esp", @"box esp", @"corner box", @"skeleton esp", @"bone esp", @"head esp", @"health esp", @"name esp", @"distance esp", @"weapon esp", @"ammo esp", @"item esp", @"loot esp", @"object esp", @"vehicle esp", @"trap esp", @"chest esp", @"radar esp",
                @"wallhack", @"wall hack", @"walls", @"wallbang", @"wall bang", @"chams", @"xqz", @"glow esp", @"glowhack", @"glow hack", @"outline esp", @"through walls", @"snapline", @"snaplines", @"line esp", @"radar", @"radar cheat", @"radar overlay", @"radar config", @"radar hack", @"radarhack", @"2d radar", @"3d radar", @"minimap hack", @"stream proof", @"streamproof", @"obs proof", @"obsproof", @"screenshot cleaner", @"screenshot bypass",
                @"no recoil", @"norecoil", @"anti recoil", @"antirecoil", @"recoil control", @"recoil script", @"rcs cheat", @"rcs config", @"rcs macro", @"rcs recoil", @"rcs script", @"spray control", @"spread control", @"nospread", @"no spread", @"no sway", @"nosway", @"no shake", @"weapon sway",
                @"bhop", @"bunnyhop", @"bunny hop", @"auto strafe", @"autostrafe", @"edge jump", @"edgejump", @"longjump", @"long jump", @"jumpbug", @"jump bug", @"edgebug", @"edge bug", @"speedhack", @"speed hack", @"flyhack", @"fly hack", @"noclip", @"no clip", @"teleport hack", @"teleport cheat", @"third person", @"thirdperson",
                @"skin changer", @"skinchanger", @"knife changer", @"glove changer", @"inventory changer", @"model changer", @"unlock all", @"unlockall", @"unlocker", @"soft unlock", @"softunlock", @"camo unlocker", @"operator unlocker", @"cosmetic unlocker",
                @"macro recoil", @"mouse macro", @"lua macro", @"bloody macro", @"logitech macro", @"ghub recoil", @"razer recoil", @"ahk recoil", @"ahk trigger", @"autohotkey recoil", @"recoil lua", @"rapid fire macro");
        }

        private static void AddCheatBuildAndSourceExpansionRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"cheat", @"cheats", @"hack", @"hacks", @"trainer", @"game trainer", @"mod menu", @"modmenu", @"loader", @"loader exe", @"loader download", @"loader source", @"loader src", @"loader project", @"loader build", @"cheat loader", @"private loader", @"public loader", @"external loader", @"internal loader", @"paid loader", @"subscription loader", @"slotted loader", @"invite loader", @"undetected loader", @"p2c loader", @"pay2cheat loader", @"pay to cheat loader", @"paste loader", @"crack loader", @"cracked loader", @"leak loader", @"leaked loader", @"p2c", @"pay2cheat", @"pay to cheat", @"paste", @"paste cheat", @"crack cheat", @"cracked cheat", @"leak cheat", @"leaked cheat",
                @"source", @"source code", @"src", @"cheat source", @"hack source", @"cheat src", @"hack src", @"source leak", @"leaked source", @"paste source", @"cheat base", @"base cheat", @"external base", @"internal base", @"sdk base", @"cheat sdk", @"game sdk", @"source sdk", @"offsets", @"offset dumper", @"netvar dumper", @"schema dumper", @"sdk dumper", @"class dumper", @"dumped sdk",
                @"external", @"internal", @"external cheat", @"internal cheat", @"kernel cheat", @"ring0 cheat", @"ring 0 cheat", @"ring-0 cheat", @"ring_0 cheat", @"ring0 driver", @"ring0 module", @"ring0 bypass", @"ring0 kernel", @"ring 0 driver", @"r0 cheat", @"r0 driver", @"r3 cheat", @"user mode cheat", @"usermode cheat", @"user-mode cheat", @"kernel mode cheat", @"kernelmode cheat", @"kernel-mode cheat", @"km cheat", @"um cheat", @"overlay cheat", @"external overlay", @"internal dll", @"cheat dll", @"hack dll", @"protected build", @"release build", @"debug build",
                @"entity list", @"entitylist", @"client dll", @"engine dll", @"viewmatrix", @"view matrix", @"world to screen", @"w2s", @"bone matrix", @"bone esp", @"game offsets", @"signature scan", @"sig scan", @"pattern scan", @"pattern scanner", @"memory reader", @"memory writer", @"readprocessmemory", @"writeprocessmemory", @"rpm wpm", @"process memory", @"handle hijack", @"handle hijacking",
                @"cheat config", @"rage config", @"legit config", @"hvh config", @"cfg rage", @"cfg legit", @"lua script", @"cheat lua", @"script hub", @"executor script", @"pastebin script", @"script loader");
        }

        private static void AddInjectorKernelDriverExpansionRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"injector", @"dll injector", @"game injector", @"process injector", @"inject dll", @"dll inject", @"loadlibrary", @"loadlibrary injector", @"manual map", @"manualmap", @"manual mapper", @"manualmapping", @"manual mapping", @"reflective loader", @"reflective dll", @"shellcode loader", @"process hollowing", @"thread hijack", @"thread hijacking", @"apc injection", @"iat hook", @"ept hook", @"hooking", @"detour", @"midfunction hook", @"vmt hook", @"shadow vmt",
                @"extreme injector", @"xenos injector", @"process hacker injector", @"saz injector", @"injector v3", @"injector x64", @"dll loader", @"module loader", @"cheat loader", @"private loader", @"public loader", @"shellcode loader", @"reflective loader", @"manualmap loader", @"manual map loader", @"loadlibrary loader", @"injection loader",
                @"kernel mapper", @"driver mapper", @"driver loader", @"sys loader", @"kernel driver", @"unsigned driver", @"vulnerable driver", @"ring0", @"ring 0", @"ring-0", @"ring_0", @"ring0 driver", @"ring0 mapper", @"ring0 bypass", @"ring0 cheat", @"r0 driver", @"r0 mapper", @"kernelmode", @"kernel-mode", @"dse bypass", @"dsefix", @"dse patch", @"patchguard bypass", @"kernel hook", @"kernel read", @"kernel write", @"kernel memory", @"kernel communication", @"ioctl cheat", @"deviceiocontrol cheat", @"physmem", @"physical memory", @"mmcopyvirtualmemory", @"zwreadvirtualmemory", @"zwwritevirtualmemory", @"kernel rpm", @"kernel wpm",
                @"kdmapper", @"kd mapper", @"kdu", @"drvmap", @"drvmapper", @"gdrvloader", @"intel driver", @"iqvw64e", @"iqvw64e.sys", @"capcom", @"capcom.sys", @"gdrv", @"gdrv.sys", @"rtcore64", @"rtcore64.sys", @"dbutil", @"dbutil_2_3", @"eneio", @"eneio64", @"winring0", @"winring0x64", @"mhyprot", @"mhyprot2", @"asrdrv", @"asrdrv10", @"asrdrv101", @"zamguard", @"amifldrv", @"inpoutx64", @"inpout32", @"inpoutx64.sys", @"rwdrv", @"phymem", @"physmem", @"physmeme", @"rtkio", @"vboxdrv exploit", @"vuln driver");
        }

        private static void AddSpooferCleanerExpansionRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"spoofer", @"hwid spoofer", @"hwid spoof", @"hwid spoofing", @"hwid bypass", @"hwid reset", @"hwid cleaner", @"hwid changer", @"serial spoofer", @"serial spoof", @"serial changer", @"disk spoofer", @"disk serial", @"volume serial", @"volume id", @"mac spoofer", @"mac spoof", @"mac changer", @"bios spoofer", @"smbios spoofer", @"uuid spoofer", @"motherboard spoofer", @"gpu spoofer", @"nic spoofer", @"tpm bypass", @"secure boot bypass", @"raid0 unban", @"raid 0 unban", @"raid0 spoof", @"raid 0 spoof",
                @"unban", @"unban tool", @"ban bypass", @"ban evasion", @"shadowban bypass", @"shadow ban bypass", @"perm spoof", @"perm spoofer", @"temp spoof", @"temp spoofer", @"perm unban", @"permanent spoof", @"permanent spoofer",
                @"cleaner", @"trace cleaner", @"traces cleaner", @"pc cleaner", @"deep cleaner", @"log cleaner", @"journal cleaner", @"usn cleaner", @"mft cleaner", @"prefetch cleaner", @"registry cleaner", @"event log cleaner", @"recent files cleaner", @"shellbag cleaner", @"artifact cleaner", @"evidence cleaner", @"clean traces", @"wipe traces", @"remove traces", @"delete traces", @"clear traces", @"cleaner bat", @"cleaner script", @"cleaner tool", @"temp cleaner", @"cache cleaner", @"history cleaner", @"download cleaner", @"steam cleaner", @"discord cleaner", @"browser cleaner");
        }

        private static void AddExternalHardwareAssistExpansionRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"dma", @"dma cheat", @"dma radar", @"dma esp", @"dma firmware", @"dma board", @"dma card", @"dma fuser", @"fuser", @"pcileech", @"pci leech", @"memprocfs", @"leechcore", @"screamer pci", @"screamer pcie", @"pcie squirrel", @"captain dma", @"lambda dma", @"enigma x1", @"dma kmbox", @"dma overlay", @"second pc radar", @"second-pc radar", @"radar pc", @"radar cheat", @"radar only", @"radar overlay", @"radar map", @"radar stream", @"radar host", @"external radar", @"web radar", @"2pc radar", @"two pc radar",
                @"kmbox", @"km box", @"kmbox net", @"kmbox b", @"kmbox pro", @"kmbox nvideo", @"kmnet", @"km net", @"hid device cheat", @"hid spoof", @"hid mouse", @"mouse movement cheat", @"mouse aimbot", @"mouse input cheat", @"interception driver", @"interception mouse", @"input emulator", @"input spoof", @"usb host shield",
                @"arduino aimbot", @"arduino colorbot", @"arduino triggerbot", @"arduino recoil", @"arduino leonardo", @"arduino micro", @"teensy aimbot", @"teensy", @"raspberry pi pico", @"pico aimbot", @"pico recoil", @"colorbot", @"color bot", @"pixelbot", @"pixel bot", @"screen capture bot", @"capture card cheat", @"ai aimbot", @"yolo aimbot", @"opencv aimbot", @"python colorbot", @"python aimbot");
        }

        private static void AddProviderAndProjectExpansionRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"unknowncheats", @"uc forum", @"guidedhacking", @"guided hacking", @"elitepvpers", @"mpgh", @"yougame", @"cheat forum", @"cheat forums", @"cheat marketplace", @"cheat provider", @"cheat providers", @"cheat seller", @"cheat shop", @"cheat store", @"cheat subscription", @"private cheat", @"slotted cheat", @"invite only cheat",
                @"aimware", @"neverlose", @"gamesense", @"skeet", @"onetap", @"otc", @"otcv3", @"otcv4", @"fatality", @"primordial", @"rifk7", @"legendware", @"interium", @"pandora", @"nixware", @"memesense", @"plaguecheat", @"mutiny", @"ev0lve", @"evolve cheat", @"iniuria", @"midnight", @"airflow", @"monolith", @"supremacy", @"sensum", @"weave", @"millionware", @"million ware", @"spirthack", @"spirit hack", @"ezfrags", @"horizon cheat", @"nemesis cheat", @"rawetrip", @"weebware", @"rifk", @"airflow cheat", @"oxide.wtf", @"oxide cheat",
                @"osiris", @"nullhooks", @"qo0", @"aimtux", @"cathook", @"lmaobox", @"nullcore", @"rijin", @"fedoraware", @"ateris", @"darkstorm", @"ncc tf2", @"duke tf2", @"riptide cheat", @"lithium cheat", @"fanta cheat", @"mirror cheat", @"dynago", @"vengeance cheat",
                @"vape v4", @"vape lite", @"vape client", @"drip lite", @"whiteout", @"entropy", @"dream advanced", @"slapp", @"slapp.in", @"antic", @"karma client", @"raven b+", @"raven bplus", @"raven xd", @"meteor client", @"wurst client", @"impact client", @"liquidbounce", @"aristois", @"sigma client", @"inertia client", @"future client", @"konas", @"rusherhack", @"pyro client", @"kami blue", @"lambda client", @"bleachhack", @"salhack", @"phobos", @"seppuku", @"moneymod", @"novoline", @"rise client", @"moon client", @"tenacity client", @"astolfo", @"zeroday client", @"exhibition client", @"sigma jello", @"liquid bounce", @"impact premium", @"azura client", @"flux client",
                @"synapse x", @"synapsex", @"krnl", @"jjsploit", @"scriptware", @"script ware", @"fluxus", @"solara executor", @"solara", @"oxygen u", @"oxygen executor", @"evon executor", @"delta executor", @"codex executor", @"arceus x", @"electron executor", @"hydrogen executor", @"trigon evo", @"vegax", @"nihon executor", @"sirhurt", @"protosmasher", @"sentinel executor", @"rc7 executor", @"elysian executor", @"calamari executor", @"kiwi x", @"roexec",
                @"ring-1", @"ring1", @"engineowning", @"aimjunkies", @"artificialaiming", @"iwantcheats", @"interwebz", @"systemcheats", @"proofcore", @"klar.gg", @"phantomoverlay", @"kernaim", @"securecheats", @"skycheats", @"x22cheats", @"x22", @"battlelog", @"cheater.fun", @"darkaim", @"zhexcheats", @"sync.top", @"novolinehook", @"kernaim", @"skycheats", @"lavicheats", @"cobalt solutions", @"hyperion cheats", @"ghostaim", @"ghost aim", @"woofer", @"woofer pro", @"verse spoofer", @"sync spoofer", @"apple cleaner", @"bt cleaner", @"tmac spoofer");
        }

        private static void AddGameSpecificExpansionRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"cs2 cheat", @"cs2 hack", @"cs2 external", @"cs2 internal", @"cs2 esp", @"cs2 wallhack", @"cs2 aimbot", @"cs2 triggerbot", @"cs2 skinchanger", @"cs2 skin changer", @"cs2 hvh", @"cs2 rage", @"cs2 legit", @"cs2 cheat source", @"cs2 offsets", @"cs2 dumper", @"counter strike 2 cheat",
                @"csgo cheat", @"csgo hack", @"csgo external", @"csgo internal", @"csgo esp", @"csgo aimbot", @"csgo triggerbot", @"csgo hvh", @"csgo skinchanger", @"csgo paste", @"csgo source", @"csgo offsets",
                @"valorant cheat", @"valorant hack", @"valorant triggerbot", @"valorant colorbot", @"valorant pixelbot", @"valorant aimbot", @"valorant esp", @"valorant spoofer", @"valorant tpm bypass", @"valorant secure boot bypass", @"valorant arduino", @"valorant kmbox", @"valorant dma", @"vanguard spoofer", @"vgk bypass",
                @"fortnite cheat", @"fortnite hack", @"fortnite aimbot", @"fortnite softaim", @"fortnite soft aim", @"fortnite esp", @"fortnite dma", @"fortnite spoofer", @"fortnite unlocker", @"fortnite cleaner", @"fortnite external", @"fortnite internal", @"fortnite triggerbot", @"fortnite dev", @"fortnite private cheat",
                @"apex cheat", @"apex legends cheat", @"apex hack", @"apex aimbot", @"apex esp", @"apex dma", @"apex spoofer", @"apex recoil", @"apex no recoil", @"apex external", @"apex internal", @"apex glow", @"r5apex cheat",
                @"warzone cheat", @"warzone hack", @"warzone aimbot", @"warzone esp", @"warzone unlocker", @"warzone spoofer", @"warzone cleaner", @"warzone soft unlock", @"warzone dma", @"mw3 cheat", @"mw2 cheat", @"mw2019 cheat", @"cod cheat", @"cod hack", @"cod unlocker", @"ricochet bypass",
                @"rust cheat", @"rust hack", @"rust esp", @"rust recoil", @"rust recoil script", @"rust script", @"rust spoofer", @"rust dma", @"rust external", @"rust internal", @"rust no recoil", @"rust bloody script", @"rust logitech script",
                @"tarkov cheat", @"tarkov hack", @"eft cheat", @"eft hack", @"eft esp", @"eft radar", @"eft dma", @"eft spoofer", @"eft external", @"eft loot esp", @"escape from tarkov cheat",
                @"r6 cheat", @"r6 hack", @"rainbow six cheat", @"rainbow six hack", @"siege cheat", @"siege hack", @"siege recoil", @"r6 recoil", @"r6 no recoil", @"r6 unlocker", @"r6 spoofer", @"r6 dma",
                @"fivem cheat", @"fivem hack", @"fivem executor", @"fivem lua", @"fivem lua executor", @"fivem spoofer", @"fivem triggerbot", @"fivem menu", @"lua executor", @"gta cheat", @"gta hack", @"gta mod menu", @"gta online menu", @"redm cheat",
                @"minecraft cheat", @"minecraft hack", @"minecraft client", @"minecraft ghost client", @"minecraft autoclicker", @"minecraft auto clicker", @"minecraft reach", @"minecraft killaura", @"minecraft aimassist", @"minecraft xray", @"bedwars cheat", @"hypixel cheat", @"hypixel client", @"forge hacked client", @"fabric hacked client",
                @"roblox executor", @"roblox exploit", @"roblox cheat", @"roblox script executor", @"roblox aimbot", @"roblox esp", @"roblox lua", @"roblox script hub", @"roblox injector", @"roblox bypass", @"byfron bypass", @"hyperion bypass",
                @"overwatch cheat", @"overwatch 2 cheat", @"ow2 cheat", @"ow2 aimbot", @"ow2 triggerbot", @"ow2 colorbot", @"overwatch colorbot", @"paladins cheat",
                @"pubg cheat", @"pubg hack", @"pubg esp", @"pubg radar", @"pubg dma", @"pubg mobile cheat", @"bgmi cheat", @"free fire cheat", @"freefire cheat",
                @"destiny 2 cheat", @"destiny cheat", @"destiny 2 recovery", @"destiny 2 aimbot", @"destiny 2 esp",
                @"dayz cheat", @"dayz hack", @"arma cheat", @"arma hack", @"squad cheat", @"battlefield cheat", @"bf2042 cheat", @"the finals cheat", @"xdefiant cheat", @"helldivers cheat");
        }

        private static void AddLoaderExpansionRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score, bool includeStandaloneLoader)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"cheat loader", @"private loader", @"public loader", @"external loader", @"internal loader", @"paid loader", @"subscription loader", @"slotted loader", @"invite loader", @"invite-only loader", @"undetected loader",
                @"p2c loader", @"pay2cheat loader", @"pay to cheat loader", @"cheat subscription loader", @"cheat client loader", @"provider loader", @"loader panel", @"loader auth", @"loader login", @"loader keyauth", @"keyauth loader",
                @"loader source", @"loader src", @"loader project", @"loader build", @"loader release", @"loader crack", @"crack loader", @"cracked loader", @"loader leak", @"leak loader", @"leaked loader", @"paste loader",
                @"loader bypass", @"loader injector", @"injector loader", @"dll loader", @"module loader", @"manual map loader", @"manualmap loader", @"loadlibrary loader", @"reflective loader", @"shellcode loader", @"driver loader", @"kernel loader", @"sys loader",
                @"eac loader", @"battleye loader", @"be loader", @"vanguard loader", @"vgk loader", @"faceit loader", @"ricochet loader",
                @"cs2 loader", @"csgo loader", @"valorant loader", @"fortnite loader", @"apex loader", @"warzone loader", @"cod loader", @"rust loader", @"tarkov loader", @"eft loader", @"r6 loader", @"fivem loader", @"roblox loader", @"minecraft loader");

            if (!includeStandaloneLoader)
            {
                return;
            }

            AddRules(rules, category, label, severity, confidence, score,
                @"loader", @"loader.exe", @"loader.dll", @"loader.sys", @"loader.bin", @"loader.zip", @"loader.rar", @"loader.7z", @"loader.bat", @"loader.ps1", @"loader.cpp", @"loader.h", @"loader.hpp", @"loader.cs", @"loader.py", @"loader.lua", @"loader.config", @"loader.json");
        }

        private static void AddInstalledProgramExpansionRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"wemod", @"cheat engine", @"cheatengine", @"artmoney", @"cosmos", @"cosmos cheat engine", @"plitch", @"fling trainer", @"aurora trainer", @"trainer", @"game trainer", @"fearless cheat engine", @"cheat table", @"ct file",
                @"ida", @"ida pro", @"ida free", @"hex-rays", @"hex rays", @"ghidra", @"binary ninja", @"hopper", @"radare2", @"rizin", @"cutter", @"x64dbg", @"x32dbg", @"ollydbg", @"windbg", @"dnspy", @"dnspyex", @"ilspy", @"de4dot", @"reclass", @"reclass.net", @"scylla", @"scyllahide", @"pe-bear", @"pestudio", @"hxd", @"process hacker", @"system informer", @"process monitor", @"procmon", @"process explorer", @"wireshark", @"fiddler", @"charles proxy", @"http debugger", @"cheat tool", @"memory editor", @"memory scanner");
        }


        private static void AddShortAcronymFileNameRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            // Short tokens are limited to filename/folder-style scans to reduce browser/history false positives.
            AddRules(rules, category, label, severity, confidence, score,
                @"esp", @"rcs", @"fov", @"hvh", @"aa", @"bhop", @"w2s", @"rpm", @"wpm", @"r0", @"r3", @"km", @"um",
                @"ring0", @"ring 0", @"ring-0", @"ring_0", @"radar", @"chams", @"resolver", @"backtrack", @"antiaim", @"glow", @"walls", @"trigger", @"rage", @"legit");
        }

        private static void AddSingleWordCheatTermRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score, bool includeRiskyStandaloneTerms)
        {
            // These are intentionally grouped because one-word terms are useful but need careful review.
            // Strong feature/tool words are applied normally. Broad words are added with lower score/confidence.
            AddRules(rules, category, label, severity, confidence, score,
                @"aimbot", @"triggerbot", @"wallhack", @"ragebot", @"legitbot", @"spinbot", @"silentaim", @"aimlock", @"aimassist",
                @"esp", @"radar", @"chams", @"snaplines", @"xray",
                @"rcs", @"norecoil", @"nospread", @"rapidfire", @"autofire", @"bhop", @"bunnyhop", @"autostrafe",
                @"antiaim", @"resolver", @"backtrack", @"fakelag", @"desync", @"autowall", @"wallbang",
                @"softaim", @"smoothaim", @"skinchanger", @"unlocker", @"spoofer", @"injector", @"mapper", @"loader", @"bypass",
                @"ring0", @"ring3", @"kernelmode", @"usermode", @"manualmap", @"loadlibrary",
                @"pcileech", @"memprocfs", @"leechcore", @"kmbox", @"colorbot", @"pixelbot", @"autoclicker", @"keyauth", @"p2c", @"hvh");

            AddRules(rules, category, label, severity, Math.Max(45, confidence - 8), Math.Max(6, score - 8),
                @"glow", @"skeleton", @"walls", @"recoil", @"fov", @"hitbox", @"hitboxes", @"bone", @"bones", @"prediction", @"vischeck",
                @"dma", @"macros", @"syscall", @"hooking", @"detour", @"trampoline", @"cracked", @"leaked", @"undetected");

            if (!includeRiskyStandaloneTerms)
            {
                return;
            }

            AddRules(rules, category, "Weak keyword hit", Severity.Low, 48, 8,
                @"cheat", @"hack", @"hacks", @"trainer", @"modmenu", @"mod-menu", @"executor", @"exploit", @"overlay", @"paste", @"crack",
                @"offsets", @"netvars", @"signatures", @"patternscan", @"sigscan", @"w2s", @"rpm", @"wpm", @"r0", @"r3",
                @"eac", @"battleye", @"vanguard", @"faceit", @"ricochet", @"vgk", @"vgc", @"dse", @"patchguard",
                @"unban", @"spoof", @"serials", @"slotted");

            AddRules(rules, category, "Context-needed keyword hit", Severity.Low, 40, 4,
                @"external", @"internal", @"menu", @"driver", @"sdk", @"dump", @"dumper", @"trace", @"traces", @"private", @"invite", @"auth", @"panel");
        }

        private static void AddCheatSourceFileNameRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score)
        {
            AddRules(rules, category, label, severity, confidence, score,
                @"esp.cpp", @"esp.h", @"esp.hpp", @"esp.cs", @"esp.lua", @"esp.py", @"visuals.cpp", @"visuals.h", @"visuals.hpp", @"visuals.cs", @"visuals.lua", @"visuals.py",
                @"aimbot.cpp", @"aimbot.h", @"aimbot.hpp", @"aimbot.cs", @"aimbot.lua", @"aimbot.py", @"aim.cpp", @"aim.h", @"aimassist.cpp", @"aimassist.h",
                @"triggerbot.cpp", @"triggerbot.h", @"trigger.cpp", @"trigger.h", @"ragebot.cpp", @"ragebot.h", @"legitbot.cpp", @"legitbot.h",
                @"rcs.cpp", @"rcs.h", @"rcs.hpp", @"recoil.cpp", @"recoil.h", @"norecoil.cpp", @"norecoil.h", @"recoil.lua", @"recoil.py",
                @"radar.cpp", @"radar.h", @"radar.hpp", @"radar.cs", @"radar.lua", @"radar.py", @"overlay.cpp", @"overlay.h", @"overlay.hpp",
                @"chams.cpp", @"chams.h", @"glow.cpp", @"glow.h", @"skinchanger.cpp", @"skinchanger.h", @"resolver.cpp", @"resolver.h", @"antiaim.cpp", @"antiaim.h",
                @"offsets.cpp", @"offsets.h", @"offsets.json", @"offsets.hpp", @"sdk.cpp", @"sdk.h", @"netvars.cpp", @"netvars.h", @"signatures.cpp", @"signatures.h",
                @"driver.cpp", @"driver.h", @"driver.hpp", @"kernel.cpp", @"kernel.h", @"ring0.cpp", @"ring0.h", @"mapper.cpp", @"mapper.h", @"injector.cpp", @"injector.h",
                @"loader.cpp", @"loader.h", @"loader.hpp", @"loader.cs", @"loader.py", @"loader.lua", @"cheatloader.cpp", @"cheatloader.h", @"cheat_loader.cpp", @"cheat_loader.h");
        }

        private static void AddRules(List<FileNameRule> rules, string category, string label, Severity severity, int confidence, int score, params string[] tokens)
        {
            foreach (string token in tokens)
            {
                AddRule(rules, token, category, label, severity, confidence, score);
            }
        }

        private static void AddRule(List<FileNameRule> rules, string token, string category, string label, Severity severity, int confidence, int score)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return;
            }

            string normalizedToken = token.Trim();
            foreach (FileNameRule existing in rules)
            {
                if (string.Equals(existing.Token, normalizedToken, System.StringComparison.OrdinalIgnoreCase)
                    && string.Equals(existing.Category, category, System.StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
            }

            rules.Add(new FileNameRule
            {
                Token = normalizedToken,
                Category = category,
                Label = label,
                Severity = severity,
                Confidence = confidence,
                Score = score
            });
        }

    }
}