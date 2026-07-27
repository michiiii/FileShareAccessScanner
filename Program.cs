// FileShareAccessScanner
//
// High-performance, one-pass scanner for critical file/share permissions.
// Target: C# 7.3 / .NET Framework 4.7 / x64
// External NuGet packages: none
//
// Important: This program reports matching DACL ACEs. It does not calculate a
// user's complete effective access after token expansion, deny ordering, share
// permissions, privileges, and group membership are evaluated together.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FileShareAccessScanner
{
    public static class Program
    {
        private const string UsageCollect =
            "collect <NetworkSharePath> <OutputFile> " +
            "[--workers <1-64>] [--directories-only] [--explicit-only] " +
            "[--include-deny] [--skip-reparse-points] [--no-resolve] " +
            "[--dc <DomainController>] [--domain <Domain>] [--pretty]";

        private const string UsageOverview = "overview <InputFile>";
        private const string UsageFilter = "filter <InputFile> <UsernameOrSID>";

        public static int Main(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                PrintUsage();
                return 1;
            }

            string command = args[0].ToLowerInvariant();

            try
            {
                switch (command)
                {
                    case "collect":
                        return HandleCollect(args);

                    case "overview":
                        return HandleOverview(args);

                    case "filter":
                        return HandleFilter(args);

                    case "help":
                    case "--help":
                    case "-h":
                    case "/?":
                        PrintUsage();
                        return 0;

                    default:
                        Console.Error.WriteLine("Unknown command: " + args[0]);
                        PrintUsage();
                        return 1;
                }
            }
            catch (OperationCanceledException)
            {
                Console.Error.WriteLine("Operation cancelled.");
                return 130;
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Error.WriteLine("[Access error] " + ex.Message);
                return 2;
            }
            catch (IOException ex)
            {
                Console.Error.WriteLine("[I/O error] " + ex.Message);
                return 2;
            }
            catch (SerializationException ex)
            {
                Console.Error.WriteLine("[JSON error] " + ex.Message);
                return 2;
            }
            catch (ArgumentException ex)
            {
                Console.Error.WriteLine("[Argument error] " + ex.Message);
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[Fatal] " + ex.GetType().Name + ": " + ex.Message);
                return 2;
            }
        }

        private static int HandleCollect(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: " + UsageCollect);
                return 1;
            }

            CollectOptions options = ParseCollectOptions(args, 3);
            string rootPath = args[1];
            string outputPath = args[2];

            Console.WriteLine("FileShareAccessScanner");
            Console.WriteLine("Root: " + rootPath);
            Console.WriteLine("Output: " + outputPath);
            Console.WriteLine("ACL workers: " + options.WorkerCount);
            Console.WriteLine("Files: " + (options.IncludeFiles ? "included" : "excluded"));
            Console.WriteLine("Inherited ACEs: " + (options.IncludeInherited ? "included" : "excluded"));
            Console.WriteLine("Deny ACEs: " + (options.IncludeDeny ? "included" : "excluded"));
            Console.WriteLine("Reparse traversal: " + (options.FollowReparsePoints ? "enabled (cycle-safe)" : "disabled"));
            Console.WriteLine("Name resolution: " + (options.ResolveNames ? "enabled" : "disabled"));

            if (!string.IsNullOrWhiteSpace(options.DomainController))
            {
                Console.WriteLine("SID lookup target: " + options.DomainController);
            }

            Console.WriteLine();

            var scanner = new Scanner(options);
            ScanSummary summary = scanner.ScanToJson(rootPath, outputPath);

            if (summary.Cancelled)
            {
                Console.WriteLine("Scan cancelled. Partial output was discarded.");
                return 130;
            }

            Console.WriteLine("Permissions saved to: " + summary.OutputPath);
            Console.WriteLine("Items discovered: " + summary.Discovered.ToString("N0", CultureInfo.InvariantCulture));
            Console.WriteLine("Items processed: " + summary.Processed.ToString("N0", CultureInfo.InvariantCulture));
            Console.WriteLine("Permission entries: " + summary.PermissionEntries.ToString("N0", CultureInfo.InvariantCulture));
            Console.WriteLine("Errors skipped: " + summary.Errors.ToString("N0", CultureInfo.InvariantCulture));
            Console.WriteLine("Reparse traversals skipped: " + summary.ReparsePointsSkipped.ToString("N0", CultureInfo.InvariantCulture));
            Console.WriteLine("Elapsed: " + summary.Elapsed);

            return 0;
        }

        private static CollectOptions ParseCollectOptions(string[] args, int startIndex)
        {
            var options = new CollectOptions();

            for (int index = startIndex; index < args.Length; index++)
            {
                string option = args[index].ToLowerInvariant();

                switch (option)
                {
                    case "--workers":
                    case "-workers":
                        {
                            string rawValue = ReadOptionValue(args, ref index, "--workers");
                            int workerCount;
                            if (!int.TryParse(rawValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out workerCount) ||
                                workerCount < 1 || workerCount > 64)
                            {
                                throw new ArgumentException("--workers must be an integer between 1 and 64.");
                            }

                            options.WorkerCount = workerCount;
                            break;
                        }

                    case "--directories-only":
                        options.IncludeFiles = false;
                        break;

                    case "--explicit-only":
                        options.IncludeInherited = false;
                        break;

                    case "--include-deny":
                        options.IncludeDeny = true;
                        break;

                    case "--follow-reparse-points":
                        options.FollowReparsePoints = true;
                        break;

                    case "--skip-reparse-points":
                        options.FollowReparsePoints = false;
                        break;

                    case "--no-resolve":
                        options.ResolveNames = false;
                        break;

                    case "--dc":
                    case "-dc":
                        options.DomainController = ReadOptionValue(args, ref index, "--dc");
                        break;

                    case "--domain":
                    case "-domain":
                        options.DomainFallback = ReadOptionValue(args, ref index, "--domain");
                        break;

                    case "--pretty":
                        options.PrettyJson = true;
                        break;

                    default:
                        throw new ArgumentException("Unknown collect option: " + args[index]);
                }
            }

            return options;
        }

        private static string ReadOptionValue(string[] args, ref int index, string option)
        {
            if (index + 1 >= args.Length)
            {
                throw new ArgumentException("Missing value for " + option + ".");
            }

            index++;
            string value = args[index];

            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("The value for " + option + " cannot be empty.");
            }

            return value;
        }

        private static int HandleOverview(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: " + UsageOverview);
                return 1;
            }

            List<AccessEntry> entries = LoadAccessEntries(args[1]);

            var grouped = entries
                .Where(entry => !string.IsNullOrWhiteSpace(entry.Username))
                .GroupBy(entry => entry.Username, StringComparer.OrdinalIgnoreCase)
                .Select(group => new
                {
                    Name = group.Key,
                    Count = group.Count(),
                    Paths = group.Select(entry => entry.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count()
                })
                .OrderByDescending(item => item.Count)
                .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase);

            Console.WriteLine("Username\tEntries\tUniquePaths");
            Console.WriteLine(new string('-', 80));

            foreach (var item in grouped)
            {
                Console.WriteLine(item.Name + "\t" + item.Count + "\t" + item.Paths);
            }

            return 0;
        }

        private static int HandleFilter(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: " + UsageFilter);
                return 1;
            }

            List<AccessEntry> entries = LoadAccessEntries(args[1]);
            string filter = args[2];

            IEnumerable<AccessEntry> filtered = entries.Where(entry =>
                ContainsIgnoreCase(entry.Username, filter) ||
                ContainsIgnoreCase(entry.SID, filter));

            Console.WriteLine("Path\tUsername\tSID\tAccessRight\tType\tInherited");
            Console.WriteLine(new string('-', 120));

            foreach (AccessEntry entry in filtered)
            {
                Console.WriteLine(
                    (entry.Path ?? string.Empty) + "\t" +
                    (entry.Username ?? string.Empty) + "\t" +
                    (entry.SID ?? string.Empty) + "\t" +
                    (entry.AccessRight ?? string.Empty) + "\t" +
                    (entry.AccessControlType ?? string.Empty) + "\t" +
                    entry.IsInherited);
            }

            return 0;
        }

        private static bool ContainsIgnoreCase(string value, string search)
        {
            return value != null &&
                   search != null &&
                   value.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static List<AccessEntry> LoadAccessEntries(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Input file path cannot be empty.", "path");
            }

            string fullPath = Path.GetFullPath(path);

            using (var stream = new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.SequentialScan))
            {
                var serializerSettings = new DataContractJsonSerializerSettings
                {
                    MaxItemsInObjectGraph = int.MaxValue
                };

                var serializer = new DataContractJsonSerializer(
                    typeof(List<AccessEntry>),
                    serializerSettings);

                object result = serializer.ReadObject(stream);
                return result as List<AccessEntry> ?? new List<AccessEntry>();
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  " + UsageCollect);
            Console.WriteLine("  " + UsageOverview);
            Console.WriteLine("  " + UsageFilter);
            Console.WriteLine();
            Console.WriteLine("Collect options:");
            Console.WriteLine("  --workers <1-64>          Global ACL worker count. Default: 4");
            Console.WriteLine("  --directories-only       Query directory ACLs only");
            Console.WriteLine("  --explicit-only          Exclude inherited ACEs from the output");
            Console.WriteLine("  --include-deny           Include matching deny ACEs; default is allow only");
            Console.WriteLine("  --skip-reparse-points    Do not traverse junctions/reparse points");
            Console.WriteLine("  --no-resolve             Keep SIDs as Username and skip account-name lookups");
            Console.WriteLine("  --dc <server>             Additional SID lookup target for unresolved SIDs");
            Console.WriteLine("  --domain <domain>         Fallback domain prefix for unqualified lookup results");
            Console.WriteLine("  --pretty                  Indent JSON output; slower and larger");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  FileShareAccessScanner.exe collect \\\\server\\share permissions.json --workers 4");
            Console.WriteLine("  FileShareAccessScanner.exe collect \\\\server\\share permissions.json --directories-only");
            Console.WriteLine("  FileShareAccessScanner.exe overview permissions.json");
            Console.WriteLine("  FileShareAccessScanner.exe filter permissions.json DOMAIN\\User");
        }
    }

    internal sealed class CollectOptions
    {
        public CollectOptions()
        {
            WorkerCount = 4;
            WorkQueueCapacity = 4096;
            ResultQueueCapacity = 8192;
            IncludeFiles = true;
            IncludeInherited = true;
            IncludeDeny = false;
            FollowReparsePoints = true;
            ResolveNames = true;
            PrettyJson = false;
        }

        public int WorkerCount { get; set; }
        public int WorkQueueCapacity { get; set; }
        public int ResultQueueCapacity { get; set; }
        public bool IncludeFiles { get; set; }
        public bool IncludeInherited { get; set; }
        public bool IncludeDeny { get; set; }
        public bool FollowReparsePoints { get; set; }
        public bool ResolveNames { get; set; }
        public bool PrettyJson { get; set; }
        public string DomainController { get; set; }
        public string DomainFallback { get; set; }
    }

    internal sealed class Scanner
    {
        private readonly CollectOptions _options;

        public Scanner(CollectOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            _options = options;
        }

        public ScanSummary ScanToJson(string rootPath, string outputPath)
        {
            if (string.IsNullOrWhiteSpace(rootPath))
            {
                throw new ArgumentException("Network share path cannot be empty.", "rootPath");
            }

            if (string.IsNullOrWhiteSpace(outputPath))
            {
                throw new ArgumentException("Output path cannot be empty.", "outputPath");
            }

            string normalizedRoot = Path.GetFullPath(rootPath);
            string normalizedOutput = Path.GetFullPath(outputPath);

            if (Directory.Exists(normalizedOutput))
            {
                throw new ArgumentException("Output path points to a directory: " + normalizedOutput);
            }

            if (PathsEqual(normalizedRoot, normalizedOutput))
            {
                throw new ArgumentException("The output file cannot be the same path as the scan root.");
            }

            // Validate access to the root before creating any output file.
            FileAttributes rootAttributes = File.GetAttributes(normalizedRoot);
            bool rootIsDirectory = (rootAttributes & FileAttributes.Directory) != 0;

            string outputDirectory = Path.GetDirectoryName(normalizedOutput);
            if (string.IsNullOrEmpty(outputDirectory))
            {
                outputDirectory = Environment.CurrentDirectory;
            }

            Directory.CreateDirectory(outputDirectory);

            string temporaryOutput = Path.Combine(
                outputDirectory,
                "." + Path.GetFileName(normalizedOutput) + "." + Guid.NewGuid().ToString("N") + ".tmp");

            var excludedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                NormalizeComparablePath(normalizedOutput),
                NormalizeComparablePath(temporaryOutput)
            };

            string shareServer = TryGetUncServer(normalizedRoot);
            var sidResolver = new SidResolver(
                _options.ResolveNames,
                shareServer,
                _options.DomainController,
                _options.DomainFallback);

            var progress = new ProgressTracker();
            var stopwatch = Stopwatch.StartNew();
            var cancellation = new CancellationTokenSource();
            var workerFailure = new FailureBox();
            var writerFailure = new FailureBox();
            Exception producerFailure = null;
            int userCancelled = 0;
            bool outputCommitted = false;

            ConsoleCancelEventHandler cancelHandler = delegate (object sender, ConsoleCancelEventArgs eventArgs)
            {
                eventArgs.Cancel = true;
                Interlocked.Exchange(ref userCancelled, 1);
                try
                {
                    cancellation.Cancel();
                }
                catch (ObjectDisposedException)
                {
                    // The scan has already completed.
                }
            };

            bool cancelHandlerAttached = false;
            try
            {
                Console.CancelKeyPress += cancelHandler;
                cancelHandlerAttached = true;
            }
            catch (InvalidOperationException)
            {
                // Some in-memory/non-console hosts do not expose Ctrl+C events.
            }

            try
            {
                using (var workQueue = new BlockingCollection<ScanItem>(_options.WorkQueueCapacity))
                using (var resultQueue = new BlockingCollection<AccessEntry>(_options.ResultQueueCapacity))
                {
                    Task writerTask = Task.Factory.StartNew(
                        delegate
                        {
                            WriterLoop(
                                temporaryOutput,
                                resultQueue,
                                progress,
                                writerFailure,
                                cancellation);
                        },
                        CancellationToken.None,
                        TaskCreationOptions.LongRunning,
                        TaskScheduler.Default);

                    Task[] workerTasks = Enumerable.Range(0, _options.WorkerCount)
                        .Select(delegate (int workerId)
                        {
                            return Task.Factory.StartNew(
                                delegate
                                {
                                    WorkerLoop(
                                        workQueue,
                                        resultQueue,
                                        sidResolver,
                                        progress,
                                        workerFailure,
                                        cancellation);
                                },
                                CancellationToken.None,
                                TaskCreationOptions.LongRunning,
                                TaskScheduler.Default);
                        })
                        .ToArray();

                    try
                    {
                        ProduceItems(
                            normalizedRoot,
                            rootIsDirectory,
                            workQueue,
                            excludedPaths,
                            progress,
                            cancellation.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        // Normal cancellation path.
                    }
                    catch (Exception ex)
                    {
                        if (ExceptionUtility.IsFatal(ex))
                        {
                            throw;
                        }

                        producerFailure = ex;
                        cancellation.Cancel();
                    }
                    finally
                    {
                        workQueue.CompleteAdding();
                    }

                    try
                    {
                        Task.WaitAll(workerTasks);
                    }
                    catch (AggregateException ex)
                    {
                        Exception nonCancellation = ex.Flatten().InnerExceptions
                            .FirstOrDefault(inner => !(inner is OperationCanceledException));

                        if (nonCancellation != null)
                        {
                            workerFailure.TrySet(nonCancellation);
                        }

                        cancellation.Cancel();
                    }
                    finally
                    {
                        resultQueue.CompleteAdding();
                    }

                    try
                    {
                        writerTask.Wait();
                    }
                    catch (AggregateException ex)
                    {
                        Exception nonCancellation = ex.Flatten().InnerExceptions
                            .FirstOrDefault(inner => !(inner is OperationCanceledException));

                        if (nonCancellation != null)
                        {
                            writerFailure.TrySet(nonCancellation);
                        }

                        cancellation.Cancel();
                    }
                }

                bool cancelled = Interlocked.CompareExchange(ref userCancelled, 0, 0) != 0;
                stopwatch.Stop();
                progress.Complete(cancelled);

                if (writerFailure.Value != null)
                {
                    throw new IOException(
                        "Writing the JSON output failed: " + writerFailure.Value.Message,
                        writerFailure.Value);
                }

                if (workerFailure.Value != null)
                {
                    throw new IOException(
                        "A scanner worker failed: " + workerFailure.Value.Message,
                        workerFailure.Value);
                }

                if (producerFailure != null)
                {
                    throw new IOException(
                        "Filesystem enumeration failed: " + producerFailure.Message,
                        producerFailure);
                }

                var summary = new ScanSummary
                {
                    OutputPath = normalizedOutput,
                    Discovered = progress.Discovered,
                    Processed = progress.Processed,
                    PermissionEntries = progress.PermissionEntries,
                    Errors = progress.Errors,
                    ReparsePointsSkipped = progress.ReparsePointsSkipped,
                    Elapsed = stopwatch.Elapsed,
                    Cancelled = cancelled
                };

                if (cancelled)
                {
                    return summary;
                }

                CommitTemporaryFile(temporaryOutput, normalizedOutput);
                outputCommitted = true;
                return summary;
            }
            finally
            {
                if (cancelHandlerAttached)
                {
                    Console.CancelKeyPress -= cancelHandler;
                }

                cancellation.Dispose();

                if (!outputCommitted)
                {
                    TryDeleteFile(temporaryOutput);
                }
            }
        }

        private void ProduceItems(
            string rootPath,
            bool rootIsDirectory,
            BlockingCollection<ScanItem> workQueue,
            HashSet<string> excludedPaths,
            ProgressTracker progress,
            CancellationToken cancellationToken)
        {
            if (rootIsDirectory || _options.IncludeFiles)
            {
                AddWorkItem(
                    workQueue,
                    new ScanItem(rootPath, rootIsDirectory),
                    progress,
                    cancellationToken);
            }

            if (!rootIsDirectory)
            {
                return;
            }

            var directories = new Stack<DirectoryInfo>();
            directories.Push(new DirectoryInfo(rootPath));

            // A reparse point can lead back to an ancestor under a different path.
            // Track the underlying Windows directory identity, not only the path, so
            // following DFS links and junctions cannot create an endless traversal.
            var visitedIdentities = new HashSet<DirectoryIdentity>();
            var visitedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            DirectoryIdentity rootIdentity;
            if (DirectoryIdentityReader.TryGet(rootPath, out rootIdentity))
            {
                visitedIdentities.Add(rootIdentity);
            }
            visitedPaths.Add(NormalizeComparablePath(rootPath));

            while (directories.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                DirectoryInfo directory = directories.Pop();

                try
                {
                    foreach (FileSystemInfo item in directory.EnumerateFileSystemInfos())
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        // FileSystemInfo.FullName is already absolute. Avoid normalizing every
                        // item merely to compare it with the two excluded output paths.
                        if (excludedPaths.Contains(item.FullName))
                        {
                            continue;
                        }

                        FileAttributes attributes;
                        try
                        {
                            attributes = item.Attributes;
                        }
                        catch (Exception ex)
                        {
                            if (ExceptionUtility.IsFatal(ex))
                            {
                                throw;
                            }

                            progress.RecordError(item.FullName, ex);
                            continue;
                        }

                        bool isDirectory = (attributes & FileAttributes.Directory) != 0;
                        bool isReparsePoint = (attributes & FileAttributes.ReparsePoint) != 0;

                        if (isDirectory || _options.IncludeFiles)
                        {
                            AddWorkItem(
                                workQueue,
                                new ScanItem(item.FullName, isDirectory),
                                progress,
                                cancellationToken);
                        }

                        if (!isDirectory)
                        {
                            continue;
                        }

                        if (isReparsePoint && !_options.FollowReparsePoints)
                        {
                            progress.IncrementReparsePointSkipped();
                            continue;
                        }

                        DirectoryIdentity identity;
                        if (DirectoryIdentityReader.TryGet(item.FullName, out identity))
                        {
                            if (!visitedIdentities.Add(identity))
                            {
                                progress.IncrementReparsePointSkipped();
                                continue;
                            }
                        }
                        else
                        {
                            string comparablePath = NormalizeComparablePath(item.FullName);
                            if (!visitedPaths.Add(comparablePath))
                            {
                                progress.IncrementReparsePointSkipped();
                                continue;
                            }

                            // Without a stable identity an unresolved reparse target
                            // cannot be followed safely: its textual path may grow on
                            // every cycle and therefore evade path-based detection.
                            if (isReparsePoint)
                            {
                                progress.RecordError(
                                    item.FullName,
                                    new IOException("Could not identify the reparse-point target safely."));
                                progress.IncrementReparsePointSkipped();
                                continue;
                            }
                        }

                        directories.Push(new DirectoryInfo(item.FullName));
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    if (ExceptionUtility.IsFatal(ex))
                    {
                        throw;
                    }

                    // A failure in one directory must not stop the complete scan.
                    progress.RecordError(directory.FullName, ex);
                }
            }
        }

        private static void AddWorkItem(
            BlockingCollection<ScanItem> queue,
            ScanItem item,
            ProgressTracker progress,
            CancellationToken cancellationToken)
        {
            queue.Add(item, cancellationToken);
            progress.IncrementDiscovered();
        }

        private void WorkerLoop(
            BlockingCollection<ScanItem> workQueue,
            BlockingCollection<AccessEntry> resultQueue,
            SidResolver sidResolver,
            ProgressTracker progress,
            FailureBox failure,
            CancellationTokenSource cancellation)
        {
            try
            {
                foreach (ScanItem item in workQueue.GetConsumingEnumerable(cancellation.Token))
                {
                    try
                    {
                        ProcessItem(item, resultQueue, sidResolver, cancellation.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        if (ExceptionUtility.IsFatal(ex))
                        {
                            throw;
                        }

                        progress.RecordError(item.Path, ex);
                    }
                    finally
                    {
                        progress.IncrementProcessed();
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal cancellation path.
            }
            catch (Exception ex)
            {
                failure.TrySet(ex);
                cancellation.Cancel();

                if (ExceptionUtility.IsFatal(ex))
                {
                    throw;
                }
            }
        }

        private void ProcessItem(
            ScanItem item,
            BlockingCollection<AccessEntry> resultQueue,
            SidResolver sidResolver,
            CancellationToken cancellationToken)
        {
            FileSystemSecurity security;

            if (item.IsDirectory)
            {
                security = new DirectoryInfo(item.Path)
                    .GetAccessControl(AccessControlSections.Access);
            }
            else
            {
                security = new FileInfo(item.Path)
                    .GetAccessControl(AccessControlSections.Access);
            }

            // Request raw SIDs. Requesting NTAccount here would perform a name lookup for
            // every ACE before the scanner has filtered system SIDs and non-critical rights.
            AuthorizationRuleCollection rules = security.GetAccessRules(
                true,
                true,
                typeof(SecurityIdentifier));

            foreach (AuthorizationRule authorizationRule in rules)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var rule = authorizationRule as FileSystemAccessRule;
                if (rule == null)
                {
                    continue;
                }

                if (!_options.IncludeInherited && rule.IsInherited)
                {
                    continue;
                }

                if (!_options.IncludeDeny && rule.AccessControlType == AccessControlType.Deny)
                {
                    continue;
                }

                SecurityIdentifier sid = rule.IdentityReference as SecurityIdentifier;
                if (sid == null)
                {
                    try
                    {
                        sid = rule.IdentityReference.Translate(typeof(SecurityIdentifier)) as SecurityIdentifier;
                    }
                    catch (IdentityNotMappedException)
                    {
                        sid = null;
                    }
                }

                if (sid == null)
                {
                    continue;
                }

                string sidValue = sid.Value;
                if (ExcludedSidPolicy.IsExcluded(sidValue))
                {
                    continue;
                }

                List<string> rights = CriticalRights.GetMatchingRights(
                    rule.FileSystemRights,
                    item.IsDirectory);

                if (rights.Count == 0)
                {
                    continue;
                }

                string username = sidResolver.Resolve(sid);
                string accessControlType = rule.AccessControlType.ToString();

                foreach (string right in rights)
                {
                    resultQueue.Add(
                        new AccessEntry
                        {
                            Path = item.Path,
                            Username = username,
                            SID = sidValue,
                            AccessRight = right,
                            AccessControlType = accessControlType,
                            IsInherited = rule.IsInherited
                        },
                        cancellationToken);
                }
            }
        }

        private void WriterLoop(
            string temporaryOutput,
            BlockingCollection<AccessEntry> resultQueue,
            ProgressTracker progress,
            FailureBox failure,
            CancellationTokenSource cancellation)
        {
            try
            {
                using (var writer = new AccessEntryJsonWriter(temporaryOutput, _options.PrettyJson))
                {
                    foreach (AccessEntry entry in resultQueue.GetConsumingEnumerable(cancellation.Token))
                    {
                        writer.Write(entry);
                        progress.IncrementPermissionEntries();
                    }

                    writer.Complete();
                }
            }
            catch (OperationCanceledException)
            {
                // Normal cancellation path; the temporary file is discarded by the caller.
            }
            catch (Exception ex)
            {
                failure.TrySet(ex);
                cancellation.Cancel();

                if (ExceptionUtility.IsFatal(ex))
                {
                    throw;
                }
            }
        }

        private static void CommitTemporaryFile(string temporaryPath, string outputPath)
        {
            if (!File.Exists(outputPath))
            {
                File.Move(temporaryPath, outputPath);
                return;
            }

            // Prefer an atomic replacement where the target filesystem supports it.
            try
            {
                File.Replace(temporaryPath, outputPath, null);
                return;
            }
            catch (PlatformNotSupportedException)
            {
                // Use the safe move-based fallback below.
            }
            catch (IOException)
            {
                // Some SMB/filesystem targets do not implement File.Replace.
            }

            // Preserve the old output if the fallback replacement fails.
            string backupPath = outputPath + ".backup." + Guid.NewGuid().ToString("N");
            File.Move(outputPath, backupPath);

            try
            {
                File.Move(temporaryPath, outputPath);

                try
                {
                    File.Delete(backupPath);
                }
                catch (Exception ex)
                {
                    if (ExceptionUtility.IsFatal(ex))
                    {
                        throw;
                    }

                    Console.Error.WriteLine("[Warning] Could not remove old output backup: " + backupPath);
                }
            }
            catch
            {
                TryDeleteFile(outputPath);

                if (File.Exists(backupPath))
                {
                    File.Move(backupPath, outputPath);
                }

                throw;
            }
        }

        private static void TryDeleteFile(string path)
        {
            try
            {
                if (!string.IsNullOrEmpty(path) && File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
                // Best-effort cleanup only.
            }
        }

        private static bool PathsEqual(string left, string right)
        {
            return string.Equals(
                NormalizeComparablePath(left),
                NormalizeComparablePath(right),
                StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeComparablePath(string path)
        {
            string fullPath = Path.GetFullPath(path);

            while (fullPath.Length > 1 &&
                   (fullPath.EndsWith("\\", StringComparison.Ordinal) ||
                    fullPath.EndsWith("/", StringComparison.Ordinal)))
            {
                // Preserve a drive root such as C:\ and a UNC share root.
                string root = Path.GetPathRoot(fullPath);
                if (string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                fullPath = fullPath.Substring(0, fullPath.Length - 1);
            }

            return fullPath;
        }

        private static string TryGetUncServer(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return null;
            }

            string remainder;

            if (path.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
            {
                remainder = path.Substring(8);
            }
            else if (path.StartsWith("\\\\", StringComparison.Ordinal))
            {
                remainder = path.Substring(2);
            }
            else
            {
                return null;
            }

            int separator = remainder.IndexOf('\\');
            if (separator <= 0)
            {
                return null;
            }

            return remainder.Substring(0, separator);
        }
    }

    internal static class CriticalRights
    {
        // Generic access bits may be stored directly in a security descriptor.
        // Expand them with the Windows file-object GENERIC_MAPPING before testing
        // the granular FileSystemRights values.
        private const uint GenericRead = 0x80000000U;
        private const uint GenericWrite = 0x40000000U;
        private const uint GenericExecute = 0x20000000U;
        private const uint GenericAll = 0x10000000U;

        private const uint FileGenericRead = 0x00120089U;
        private const uint FileGenericWrite = 0x00120116U;
        private const uint FileGenericExecute = 0x001200A0U;
        private const uint FileAllAccess = 0x001F01FFU;

        public static List<string> GetMatchingRights(FileSystemRights rights, bool isDirectory)
        {
            uint normalizedRights = NormalizeGenericRights(
                unchecked((uint)(int)rights));

            var result = new List<string>(8);

            AddIfAllBits(
                result,
                normalizedRights,
                FileSystemRights.ChangePermissions,
                "ChangePermissions");

            AddIfAllBits(
                result,
                normalizedRights,
                FileSystemRights.TakeOwnership,
                "TakeOwnership");

            // Write is a composite right. Report it only when every component is
            // present; one overlapping write bit is not the complete Write right.
            AddIfAllBits(
                result,
                normalizedRights,
                FileSystemRights.Write,
                "Write");

            if (HasAllBits(normalizedRights, FileSystemRights.AppendData))
            {
                // AppendData and CreateDirectories share the same numeric bit.
                result.Add(isDirectory ? "CreateDirectories" : "AppendData");
            }

            if (HasAllBits(normalizedRights, FileSystemRights.WriteData))
            {
                // WriteData and CreateFiles share the same numeric bit.
                result.Add(isDirectory ? "CreateFiles" : "WriteData");
            }

            AddIfAllBits(result, normalizedRights, FileSystemRights.Delete, "Delete");
            AddIfAllBits(
                result,
                normalizedRights,
                FileSystemRights.WriteAttributes,
                "WriteAttributes");
            AddIfAllBits(
                result,
                normalizedRights,
                FileSystemRights.WriteExtendedAttributes,
                "WriteExtendedAttributes");

            return result;
        }

        private static uint NormalizeGenericRights(uint accessMask)
        {
            if ((accessMask & GenericRead) != 0U)
            {
                accessMask &= ~GenericRead;
                accessMask |= FileGenericRead;
            }

            if ((accessMask & GenericWrite) != 0U)
            {
                accessMask &= ~GenericWrite;
                accessMask |= FileGenericWrite;
            }

            if ((accessMask & GenericExecute) != 0U)
            {
                accessMask &= ~GenericExecute;
                accessMask |= FileGenericExecute;
            }

            if ((accessMask & GenericAll) != 0U)
            {
                accessMask &= ~GenericAll;
                accessMask |= FileAllAccess;
            }

            return accessMask;
        }

        private static bool HasAllBits(uint actual, FileSystemRights required)
        {
            uint requiredMask = unchecked((uint)(int)required);
            return (actual & requiredMask) == requiredMask;
        }

        private static void AddIfAllBits(
            ICollection<string> result,
            uint actual,
            FileSystemRights required,
            string name)
        {
            if (HasAllBits(actual, required))
            {
                result.Add(name);
            }
        }
    }

    internal static class ExcludedSidPolicy
    {
        private static readonly HashSet<string> ExactExcludedSids =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "S-1-5-18",      // Local System
                "S-1-3-0",       // Creator Owner
                "S-1-5-32-544"   // Builtin Administrators
            };

        public static bool IsExcluded(string sid)
        {
            if (string.IsNullOrEmpty(sid))
            {
                return false;
            }

            return ExactExcludedSids.Contains(sid) ||
                   sid.EndsWith("-520", StringComparison.Ordinal) || // Group Policy Creator Owners
                   sid.EndsWith("-512", StringComparison.Ordinal) || // Domain Admins
                   sid.EndsWith("-519", StringComparison.Ordinal);   // Enterprise Admins
        }
    }

    internal sealed class SidResolver
    {
        private readonly bool _resolveNames;
        private readonly string _shareServer;
        private readonly string _domainController;
        private readonly string _domainFallback;

        private readonly ConcurrentDictionary<string, Lazy<string>> _cache =
            new ConcurrentDictionary<string, Lazy<string>>(StringComparer.OrdinalIgnoreCase);

        public SidResolver(
            bool resolveNames,
            string shareServer,
            string domainController,
            string domainFallback)
        {
            _resolveNames = resolveNames;
            _shareServer = NormalizeServerName(shareServer);
            _domainController = NormalizeServerName(domainController);
            _domainFallback = string.IsNullOrWhiteSpace(domainFallback)
                ? null
                : domainFallback.Trim().TrimEnd('\\');
        }

        public string Resolve(SecurityIdentifier sid)
        {
            if (sid == null)
            {
                return string.Empty;
            }

            string sidValue = sid.Value;
            if (!_resolveNames)
            {
                return sidValue;
            }

            Lazy<string> lazy = _cache.GetOrAdd(
                sidValue,
                delegate (string key)
                {
                    return new Lazy<string>(
                        delegate
                        {
                            return ResolveUncached(new SecurityIdentifier(key));
                        },
                        LazyThreadSafetyMode.ExecutionAndPublication);
                });

            return lazy.Value;
        }

        private string ResolveUncached(SecurityIdentifier sid)
        {
            try
            {
                var account = sid.Translate(typeof(NTAccount)) as NTAccount;
                if (account != null && !string.IsNullOrWhiteSpace(account.Value))
                {
                    return account.Value;
                }
            }
            catch (IdentityNotMappedException)
            {
                // Try explicit lookup targets below.
            }
            catch (Exception ex)
            {
                if (ExceptionUtility.IsFatal(ex))
                {
                    throw;
                }

                // Try explicit lookup targets below.
            }

            string accountName = TryLookupOnServer(sid, _shareServer);
            if (!string.IsNullOrEmpty(accountName))
            {
                return accountName;
            }

            if (!ServersEqual(_shareServer, _domainController))
            {
                accountName = TryLookupOnServer(sid, _domainController);
                if (!string.IsNullOrEmpty(accountName))
                {
                    return accountName;
                }
            }

            return sid.Value;
        }

        private string TryLookupOnServer(SecurityIdentifier sid, string server)
        {
            if (string.IsNullOrEmpty(server))
            {
                return null;
            }

            string result = NativeAccountLookup.TryLookupAccountSid(server, sid, _domainFallback);
            if (!string.IsNullOrEmpty(result))
            {
                return result;
            }

            // Some environments expect an explicit UNC-style computer name.
            if (!server.StartsWith("\\\\", StringComparison.Ordinal))
            {
                result = NativeAccountLookup.TryLookupAccountSid("\\\\" + server, sid, _domainFallback);
            }

            return result;
        }

        private static string NormalizeServerName(string server)
        {
            if (string.IsNullOrWhiteSpace(server))
            {
                return null;
            }

            return server.Trim().TrimStart('\\');
        }

        private static bool ServersEqual(string left, string right)
        {
            return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        }
    }

    internal static class NativeAccountLookup
    {
        private const int ErrorInsufficientBuffer = 122;

        public static string TryLookupAccountSid(
            string systemName,
            SecurityIdentifier sid,
            string domainFallback)
        {
            if (sid == null)
            {
                return null;
            }

            try
            {
                byte[] sidBytes = new byte[sid.BinaryLength];
                sid.GetBinaryForm(sidBytes, 0);

                GCHandle sidHandle = GCHandle.Alloc(sidBytes, GCHandleType.Pinned);
                try
                {
                    IntPtr sidPointer = sidHandle.AddrOfPinnedObject();
                    uint nameLength = 0;
                    uint domainLength = 0;
                    SidNameUse sidNameUse;

                    NativeMethods.LookupAccountSid(
                        systemName,
                        sidPointer,
                        null,
                        ref nameLength,
                        null,
                        ref domainLength,
                        out sidNameUse);

                    int error = Marshal.GetLastWin32Error();
                    if (error != ErrorInsufficientBuffer || nameLength == 0)
                    {
                        return null;
                    }

                    if (nameLength > (uint)int.MaxValue || domainLength > (uint)int.MaxValue)
                    {
                        return null;
                    }

                    int domainCapacityValue = domainLength == 0 ? 1 : (int)domainLength;
                    var name = new StringBuilder((int)nameLength);
                    var domain = new StringBuilder(domainCapacityValue);
                    uint nameCapacity = (uint)name.Capacity;
                    uint domainCapacity = (uint)domain.Capacity;

                    bool success = NativeMethods.LookupAccountSid(
                        systemName,
                        sidPointer,
                        name,
                        ref nameCapacity,
                        domain,
                        ref domainCapacity,
                        out sidNameUse);

                    if (!success)
                    {
                        return null;
                    }

                    string accountName = name.ToString();
                    if (string.IsNullOrWhiteSpace(accountName))
                    {
                        return null;
                    }

                    string domainName = domain.ToString();
                    if (string.IsNullOrWhiteSpace(domainName))
                    {
                        domainName = domainFallback;
                    }

                    return string.IsNullOrWhiteSpace(domainName)
                        ? accountName
                        : domainName + "\\" + accountName;
                }
                finally
                {
                    sidHandle.Free();
                }
            }
            catch (DllNotFoundException)
            {
                return null;
            }
            catch (EntryPointNotFoundException)
            {
                return null;
            }
            catch (Exception ex)
            {
                if (ExceptionUtility.IsFatal(ex))
                {
                    throw;
                }

                return null;
            }
        }

        private enum SidNameUse
        {
            User = 1,
            Group,
            Domain,
            Alias,
            WellKnownGroup,
            DeletedAccount,
            Invalid,
            Unknown,
            Computer,
            Label
        }

        private static class NativeMethods
        {
            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool LookupAccountSid(
                string lpSystemName,
                IntPtr sid,
                StringBuilder name,
                ref uint cchName,
                StringBuilder referencedDomainName,
                ref uint cchReferencedDomainName,
                out SidNameUse peUse);
        }
    }

    internal sealed class AccessEntryJsonWriter : IDisposable
    {
        private readonly StreamWriter _writer;
        private readonly bool _pretty;
        private bool _first = true;
        private bool _completed;
        private bool _disposed;

        public AccessEntryJsonWriter(string path, bool pretty)
        {
            _pretty = pretty;

            var stream = new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.SequentialScan);

            _writer = new StreamWriter(stream, new UTF8Encoding(false), 64 * 1024);
            _writer.Write('[');
        }

        public void Write(AccessEntry entry)
        {
            if (entry == null)
            {
                return;
            }

            ThrowIfDisposed();

            if (!_first)
            {
                _writer.Write(',');
            }

            if (_pretty)
            {
                _writer.WriteLine();
                _writer.Write("  ");
            }

            _writer.Write('{');
            WriteStringProperty("Path", entry.Path, true);
            WriteStringProperty("Username", entry.Username, false);
            WriteStringProperty("SID", entry.SID, false);
            WriteStringProperty("AccessRight", entry.AccessRight, false);
            WriteStringProperty("AccessControlType", entry.AccessControlType, false);
            WriteBooleanProperty("IsInherited", entry.IsInherited, false);
            _writer.Write('}');

            _first = false;
        }

        public void Complete()
        {
            ThrowIfDisposed();

            if (_completed)
            {
                return;
            }

            if (_pretty && !_first)
            {
                _writer.WriteLine();
            }

            _writer.Write(']');
            _writer.Flush();
            _completed = true;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _writer.Dispose();
        }

        private void WriteStringProperty(string name, string value, bool firstProperty)
        {
            if (!firstProperty)
            {
                _writer.Write(',');
            }

            if (_pretty)
            {
                _writer.Write(' ');
            }

            WriteJsonString(_writer, name);
            _writer.Write(_pretty ? ": " : ":");
            WriteJsonString(_writer, value);
        }

        private void WriteBooleanProperty(string name, bool value, bool firstProperty)
        {
            if (!firstProperty)
            {
                _writer.Write(',');
            }

            if (_pretty)
            {
                _writer.Write(' ');
            }

            WriteJsonString(_writer, name);
            _writer.Write(_pretty ? ": " : ":");
            _writer.Write(value ? "true" : "false");
        }

        private static void WriteJsonString(TextWriter writer, string value)
        {
            if (value == null)
            {
                writer.Write("null");
                return;
            }

            writer.Write('"');

            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];

                switch (character)
                {
                    case '"':
                        writer.Write("\\\"");
                        break;

                    case '\\':
                        writer.Write("\\\\");
                        break;

                    case '\b':
                        writer.Write("\\b");
                        break;

                    case '\f':
                        writer.Write("\\f");
                        break;

                    case '\n':
                        writer.Write("\\n");
                        break;

                    case '\r':
                        writer.Write("\\r");
                        break;

                    case '\t':
                        writer.Write("\\t");
                        break;

                    default:
                        if (character < 0x20)
                        {
                            WriteUnicodeEscape(writer, character);
                        }
                        else if (char.IsHighSurrogate(character))
                        {
                            if (index + 1 < value.Length && char.IsLowSurrogate(value[index + 1]))
                            {
                                writer.Write(character);
                                writer.Write(value[++index]);
                            }
                            else
                            {
                                WriteUnicodeEscape(writer, character);
                            }
                        }
                        else if (char.IsLowSurrogate(character))
                        {
                            WriteUnicodeEscape(writer, character);
                        }
                        else
                        {
                            writer.Write(character);
                        }

                        break;
                }
            }

            writer.Write('"');
        }

        private static void WriteUnicodeEscape(TextWriter writer, char character)
        {
            writer.Write("\\u");
            writer.Write(((int)character).ToString("x4", CultureInfo.InvariantCulture));
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }
        }
    }

    internal struct DirectoryIdentity : IEquatable<DirectoryIdentity>
    {
        public DirectoryIdentity(uint volumeSerialNumber, uint fileIndexHigh, uint fileIndexLow)
        {
            VolumeSerialNumber = volumeSerialNumber;
            FileIndexHigh = fileIndexHigh;
            FileIndexLow = fileIndexLow;
        }

        public uint VolumeSerialNumber { get; private set; }
        public uint FileIndexHigh { get; private set; }
        public uint FileIndexLow { get; private set; }

        public bool Equals(DirectoryIdentity other)
        {
            return VolumeSerialNumber == other.VolumeSerialNumber &&
                   FileIndexHigh == other.FileIndexHigh &&
                   FileIndexLow == other.FileIndexLow;
        }

        public override bool Equals(object obj)
        {
            return obj is DirectoryIdentity && Equals((DirectoryIdentity)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hash = (int)VolumeSerialNumber;
                hash = (hash * 397) ^ (int)FileIndexHigh;
                return (hash * 397) ^ (int)FileIndexLow;
            }
        }
    }

    internal static class DirectoryIdentityReader
    {
        private const uint FileShareRead = 0x00000001U;
        private const uint FileShareWrite = 0x00000002U;
        private const uint FileShareDelete = 0x00000004U;
        private const uint OpenExisting = 3U;
        private const uint FileFlagBackupSemantics = 0x02000000U;

        public static bool TryGet(string path, out DirectoryIdentity identity)
        {
            identity = default(DirectoryIdentity);

            using (SafeFileHandle handle = CreateFile(
                path,
                0U,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics,
                IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    return false;
                }

                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    return false;
                }

                identity = new DirectoryIdentity(
                    information.VolumeSerialNumber,
                    information.FileIndexHigh,
                    information.FileIndexLow);
                return true;
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation fileInformation);

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }
    }

    internal sealed class ProgressTracker
    {
        private const int MaximumPrintedErrors = 20;
        private readonly Stopwatch _stopwatch = Stopwatch.StartNew();
        private readonly object _consoleLock = new object();

        private long _discovered;
        private long _processed;
        private long _permissionEntries;
        private long _errors;
        private long _reparsePointsSkipped;
        private long _lastDisplayMilliseconds;
        private int _printedErrors;
        private int _lastInteractiveLineLength;

        public long Discovered { get { return Interlocked.Read(ref _discovered); } }
        public long Processed { get { return Interlocked.Read(ref _processed); } }
        public long PermissionEntries { get { return Interlocked.Read(ref _permissionEntries); } }
        public long Errors { get { return Interlocked.Read(ref _errors); } }
        public long ReparsePointsSkipped { get { return Interlocked.Read(ref _reparsePointsSkipped); } }

        public void IncrementDiscovered()
        {
            Interlocked.Increment(ref _discovered);
        }

        public void IncrementProcessed()
        {
            long processed = Interlocked.Increment(ref _processed);

            // Sampling avoids a stopwatch and console-state check for every file.
            if ((processed & 127L) == 0L)
            {
                TryDisplay(false, false);
            }
        }

        public void IncrementPermissionEntries()
        {
            Interlocked.Increment(ref _permissionEntries);
        }

        public void IncrementReparsePointSkipped()
        {
            Interlocked.Increment(ref _reparsePointsSkipped);
        }

        public void RecordError(string path, Exception exception)
        {
            Interlocked.Increment(ref _errors);
            int printed = Interlocked.Increment(ref _printedErrors);

            if (printed <= MaximumPrintedErrors)
            {
                lock (_consoleLock)
                {
                    ClearInteractiveProgressLine();
                    Console.Error.WriteLine(
                        "[Skipped] " + path + ": " + exception.GetType().Name + ": " + exception.Message);
                }
            }
            else if (printed == MaximumPrintedErrors + 1)
            {
                lock (_consoleLock)
                {
                    ClearInteractiveProgressLine();
                    Console.Error.WriteLine("[Skipped] Further per-path errors are suppressed.");
                }
            }
        }

        public void Complete(bool cancelled)
        {
            TryDisplay(true, cancelled);

            if (!Console.IsOutputRedirected)
            {
                lock (_consoleLock)
                {
                    Console.WriteLine();
                    _lastInteractiveLineLength = 0;
                }
            }
        }

        private void TryDisplay(bool force, bool cancelled)
        {
            long elapsedMilliseconds = _stopwatch.ElapsedMilliseconds;
            long lastDisplay = Interlocked.Read(ref _lastDisplayMilliseconds);
            long interval = Console.IsOutputRedirected ? 10000L : 1000L;

            if (!force && elapsedMilliseconds - lastDisplay < interval)
            {
                return;
            }

            lock (_consoleLock)
            {
                elapsedMilliseconds = _stopwatch.ElapsedMilliseconds;
                lastDisplay = _lastDisplayMilliseconds;

                if (!force && elapsedMilliseconds - lastDisplay < interval)
                {
                    return;
                }

                _lastDisplayMilliseconds = elapsedMilliseconds;

                long discovered = Discovered;
                long processed = Processed;
                long entries = PermissionEntries;
                long errors = Errors;
                long pending = Math.Max(0L, discovered - processed);
                double seconds = Math.Max(0.001, _stopwatch.Elapsed.TotalSeconds);
                double rate = processed / seconds;

                string message = string.Format(
                    CultureInfo.InvariantCulture,
                    "{0}Processed {1:N0}/{2:N0} | pending {3:N0} | {4:N1}/s | entries {5:N0} | errors {6:N0}",
                    cancelled ? "CANCELLED | " : string.Empty,
                    processed,
                    discovered,
                    pending,
                    rate,
                    entries,
                    errors);

                if (Console.IsOutputRedirected)
                {
                    Console.WriteLine(message);
                }
                else
                {
                    int padding = Math.Max(0, _lastInteractiveLineLength - message.Length);
                    Console.Write("\r" + message + new string(' ', padding));
                    _lastInteractiveLineLength = message.Length;
                }
            }
        }

        private void ClearInteractiveProgressLine()
        {
            if (Console.IsOutputRedirected || _lastInteractiveLineLength == 0)
            {
                return;
            }

            Console.Write("\r" + new string(' ', _lastInteractiveLineLength) + "\r");
            _lastInteractiveLineLength = 0;
        }
    }

    internal sealed class ScanItem
    {
        public ScanItem(string path, bool isDirectory)
        {
            Path = path;
            IsDirectory = isDirectory;
        }

        public string Path { get; private set; }
        public bool IsDirectory { get; private set; }
    }

    internal sealed class FailureBox
    {
        private Exception _value;

        public Exception Value
        {
            get { return Interlocked.CompareExchange(ref _value, null, null); }
        }

        public void TrySet(Exception exception)
        {
            if (exception == null)
            {
                return;
            }

            Interlocked.CompareExchange(ref _value, exception, null);
        }
    }

    internal static class ExceptionUtility
    {
        public static bool IsFatal(Exception exception)
        {
            return exception is OutOfMemoryException ||
                   exception is StackOverflowException ||
                   exception is AccessViolationException ||
                   exception is SEHException ||
                   exception is AppDomainUnloadedException ||
                   exception is BadImageFormatException ||
                   exception is CannotUnloadAppDomainException ||
                   exception is ThreadAbortException;
        }
    }

    public sealed class ScanSummary
    {
        public string OutputPath { get; set; }
        public long Discovered { get; set; }
        public long Processed { get; set; }
        public long PermissionEntries { get; set; }
        public long Errors { get; set; }
        public long ReparsePointsSkipped { get; set; }
        public TimeSpan Elapsed { get; set; }
        public bool Cancelled { get; set; }
    }

    [DataContract]
    public sealed class AccessEntry
    {
        [DataMember(Name = "Path", Order = 1)]
        public string Path { get; set; }

        [DataMember(Name = "Username", Order = 2)]
        public string Username { get; set; }

        [DataMember(Name = "SID", Order = 3)]
        public string SID { get; set; }

        [DataMember(Name = "AccessRight", Order = 4)]
        public string AccessRight { get; set; }

        [DataMember(Name = "AccessControlType", Order = 5, EmitDefaultValue = false)]
        public string AccessControlType { get; set; }

        [DataMember(Name = "IsInherited", Order = 6)]
        public bool IsInherited { get; set; }
    }
}
