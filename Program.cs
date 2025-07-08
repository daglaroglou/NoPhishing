using Discord;
using Discord.WebSocket;
using Microsoft.Extensions.Configuration;
using System.Text.RegularExpressions;
using System.Collections.Concurrent;
using Newtonsoft.Json;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NoPhishing;

// Response model for Anti-Fish API
public class AntiFishResponse
{
    public bool Match { get; set; }
    public List<AntiFishMatch>? Matches { get; set; }
}

public class AntiFishMatch
{
    public string? Domain { get; set; }
    public string? Source { get; set; }
    public string? Type { get; set; }
    public bool Trust { get; set; }
}

// Response model for Phish.Sinking.Yachts API
public class SinkingYachtsResponse
{
    public List<string>? Domains { get; set; }
}

// Domain check result for three-tier validation
public class DomainCheckResult
{
    public string Domain { get; set; } = string.Empty;
    public bool IsScam { get; set; }
    public List<string> DetectionSources { get; set; } = new();
    public List<string> Details { get; set; } = new();
}

// Guild settings model for persistent storage
public class GuildSettings
{
    public ulong GuildId { get; set; }
    public bool DefendingModeActive { get; set; }
    public DateTime LastActivated { get; set; }
    public string? ActivatedBy { get; set; }
}

// Bot settings container
public class BotSettings
{
    public Dictionary<ulong, GuildSettings> Guilds { get; set; } = new();
    public DateTime LastUpdated { get; set; } = DateTime.Now;
}

// Database entities
[Table("ScamDomains")]
public class ScamDomain
{
    [Key]
    public int Id { get; set; }
    
    [Required]
    [MaxLength(255)]
    public string Domain { get; set; } = string.Empty;
    
    [MaxLength(100)]
    public string? DetectionSource { get; set; }
    
    public DateTime DateAdded { get; set; } = DateTime.UtcNow;
    
    [MaxLength(500)]
    public string? Notes { get; set; }
    
    public bool IsActive { get; set; } = true;
}

[Table("DomainReports")]
public class DomainReport
{
    [Key]
    public int Id { get; set; }
    
    [Required]
    [MaxLength(255)]
    public string Domain { get; set; } = string.Empty;
    
    [MaxLength(500)]
    public string? Reason { get; set; }
    
    public ulong ReportedByUserId { get; set; }
    
    [MaxLength(100)]
    public string ReportedByUsername { get; set; } = string.Empty;
    
    public ulong? GuildId { get; set; }
    
    [MaxLength(200)]
    public string? GuildName { get; set; }
    
    public DateTime ReportDate { get; set; } = DateTime.UtcNow;
    
    public bool IsProcessed { get; set; } = false;
    
    [MaxLength(1000)]
    public string? ProcessingNotes { get; set; }
}

[Table("DomainImportLogs")]
public class DomainImportLog
{
    [Key]
    public int Id { get; set; }
    
    [Required]
    [MaxLength(100)]
    public string Source { get; set; } = string.Empty;
    
    public DateTime ImportDate { get; set; } = DateTime.UtcNow;
    
    public int DomainsImported { get; set; }
    
    public int DomainsSkipped { get; set; }
    
    [MaxLength(1000)]
    public string? Notes { get; set; }
}

[Table("WhitelistDomains")]
public class WhitelistDomain
{
    [Key]
    public int Id { get; set; }
    
    [Required]
    [MaxLength(255)]
    public string Domain { get; set; } = string.Empty;
    
    public ulong? GuildId { get; set; } // null = global whitelist
    
    [MaxLength(200)]
    public string? GuildName { get; set; }
    
    public ulong AddedByUserId { get; set; }
    
    [MaxLength(100)]
    public string AddedByUsername { get; set; } = string.Empty;
    
    public DateTime DateAdded { get; set; } = DateTime.UtcNow;
    
    [MaxLength(500)]
    public string? Reason { get; set; }
    
    public bool IsActive { get; set; } = true;
}

[Table("ServerConfigs")]
public class ServerConfig
{
    [Key]
    public int Id { get; set; }
    
    public ulong GuildId { get; set; }
    
    [MaxLength(200)]
    public string? GuildName { get; set; }
    
    public bool AutoDeleteScamMessages { get; set; } = true;
    
    public bool SendWarningMessages { get; set; } = true;
    
    public bool LogDetections { get; set; } = true;
    
    public ulong? LogChannelId { get; set; }
    
    public bool RequireManualReview { get; set; } = false;
    
    public int ScamThreshold { get; set; } = 1; // How many sources need to detect before action
    
    public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
    
    public ulong? UpdatedByUserId { get; set; }
    
    [MaxLength(100)]
    public string? UpdatedByUsername { get; set; }
}

[Table("DetectionLogs")]
public class DetectionLog
{
    [Key]
    public int Id { get; set; }
    
    [Required]
    [MaxLength(255)]
    public string Domain { get; set; } = string.Empty;
    
    public ulong GuildId { get; set; }
    
    [MaxLength(200)]
    public string? GuildName { get; set; }
    
    public ulong UserId { get; set; }
    
    [MaxLength(100)]
    public string Username { get; set; } = string.Empty;
    
    public ulong ChannelId { get; set; }
    
    [MaxLength(100)]
    public string ChannelName { get; set; } = string.Empty;
    
    public ulong MessageId { get; set; }
    
    [MaxLength(2000)]
    public string? MessageContent { get; set; }
    
    [MaxLength(500)]
    public string DetectionSources { get; set; } = string.Empty; // JSON array of sources
    
    public DateTime DetectionDate { get; set; } = DateTime.UtcNow;
    
    public bool WasDeleted { get; set; } = false;
    
    public bool WasWarned { get; set; } = false;
    
    [MaxLength(500)]
    public string? ActionTaken { get; set; }
}

// Database context
public class NoPhishingDbContext : DbContext
{
    public DbSet<ScamDomain> ScamDomains { get; set; }
    public DbSet<DomainImportLog> DomainImportLogs { get; set; }
    public DbSet<DomainReport> DomainReports { get; set; }
    public DbSet<WhitelistDomain> WhitelistDomains { get; set; }
    public DbSet<ServerConfig> ServerConfigs { get; set; }
    public DbSet<DetectionLog> DetectionLogs { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseSqlite("Data Source=nophishing.db");
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ScamDomain>(entity =>
        {
            entity.HasIndex(e => e.Domain).IsUnique();
            entity.Property(e => e.Domain).IsRequired();
        });

        modelBuilder.Entity<DomainImportLog>(entity =>
        {
            entity.Property(e => e.Source).IsRequired();
        });

        modelBuilder.Entity<DomainReport>(entity =>
        {
            entity.Property(e => e.Domain).IsRequired();
            entity.Property(e => e.ReportedByUsername).IsRequired();
            entity.HasIndex(e => e.Domain);
            entity.HasIndex(e => e.ReportDate);
        });

        modelBuilder.Entity<WhitelistDomain>(entity =>
        {
            entity.Property(e => e.Domain).IsRequired();
            entity.Property(e => e.AddedByUsername).IsRequired();
            entity.HasIndex(e => e.Domain);
            entity.HasIndex(e => e.GuildId);
            entity.HasIndex(e => new { e.Domain, e.GuildId }).IsUnique();
        });

        modelBuilder.Entity<ServerConfig>(entity =>
        {
            entity.HasIndex(e => e.GuildId).IsUnique();
            entity.Property(e => e.GuildId).IsRequired();
        });

        modelBuilder.Entity<DetectionLog>(entity =>
        {
            entity.Property(e => e.Domain).IsRequired();
            entity.Property(e => e.Username).IsRequired();
            entity.Property(e => e.ChannelName).IsRequired();
            entity.HasIndex(e => e.Domain);
            entity.HasIndex(e => e.GuildId);
            entity.HasIndex(e => e.DetectionDate);
        });
    }
}

class Program
{
    private static DiscordSocketClient? _client;
    private static readonly ConcurrentDictionary<string, bool> _scamDomainsCache = new();
    private static readonly string BotSettingsFile = "bot_settings.json";
    private static readonly string ScamLinksUrl = "https://raw.githubusercontent.com/Discord-AntiScam/scam-links/main/list.txt";
    private static readonly string AntiFishApiUrl = "https://anti-fish.bitflow.dev/check";
    private static readonly string SinkingYachtsApiUrl = "https://phish.sinking.yachts/v2/all";
    private static BotSettings _botSettings = new();
    private static IConfiguration? _configuration;
    private static readonly HttpClient _httpClient = new();
    private static readonly ConcurrentDictionary<string, List<(string url, string source)>> _pendingScamReveals = new();
    private static readonly SemaphoreSlim _databaseLock = new(1, 1);
    private static readonly SemaphoreSlim _settingsLock = new(1, 1);

    static async Task Main(string[] args)
    {
        Console.WriteLine("NoPhishing Discord Bot Starting...");
        Console.WriteLine("=====================================");
        
        // Build configuration with user secrets
        _configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
            .AddUserSecrets<Program>()
            .AddEnvironmentVariables()
            .Build();

        // Configure HttpClient
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "NoPhishing-Discord-Bot/1.0");
        _httpClient.Timeout = TimeSpan.FromSeconds(30);

        Console.WriteLine("Starting database initialization...");
        
        // Initialize database and load scam domains
        await InitializeDatabase();
        await LoadScamDomainsFromDatabase();

        // Download and update scam domains from GitHub
        await UpdateScamDomainsFromGitHub();

        // Load bot settings (guild defending mode states)
        await LoadBotSettings();

        var domainCount = await GetScamDomainCountAsync();
        Console.WriteLine($"Database initialization complete - {domainCount} domains loaded");
        Console.WriteLine($"Bot settings loaded - {_botSettings.Guilds.Count} guild configurations");
        Console.WriteLine("=====================================");

        // Configure Discord client with only required intents
        var config = new DiscordSocketConfig
        {
            // Only request the gateway intents we actually use:
            // - Guilds: Access guild information and settings
            // - GuildMessages: Receive messages in guild channels for scanning
            // - DirectMessages: Send developer notifications via DM
            // - MessageContent: Read message content to extract URLs
            GatewayIntents = GatewayIntents.Guilds |
                           GatewayIntents.GuildMessages |
                           GatewayIntents.DirectMessages |
                           GatewayIntents.MessageContent |
                           GatewayIntents.DirectMessages
        };

        _client = new DiscordSocketClient(config);

        // Subscribe to events
        _client.Log += LogAsync;
        _client.Ready += ReadyAsync;
        _client.MessageReceived += MessageReceivedAsync;
        _client.SlashCommandExecuted += SlashCommandHandler;
        _client.ButtonExecuted += ButtonExecutedAsync;
        _client.ModalSubmitted += ModalSubmittedAsync;

        // Get bot token from configuration (user secrets, then environment variables, then appsettings.json)
        var token = _configuration["DiscordBotToken"];

        if (string.IsNullOrEmpty(token))
        {
            Console.WriteLine("😞 Discord bot token not found!");
            Console.WriteLine();
            Console.WriteLine("Please set the token using one of the following methods:");
            Console.WriteLine();
            Console.WriteLine("1. User Secrets (Recommended for development):");
            Console.WriteLine("   dotnet user-secrets set \"DiscordBotToken\" \"your_bot_token_here\"");
            Console.WriteLine("   dotnet user-secrets set \"DeveloperUserId\" \"your_discord_user_id_here\"");
            Console.WriteLine();
            Console.WriteLine("2. Environment Variable:");
            Console.WriteLine("   $env:DiscordBotToken=\"your_bot_token_here\"");
            Console.WriteLine("   $env:DeveloperUserId=\"your_discord_user_id_here\"");
            Console.WriteLine();
            Console.WriteLine("3. appsettings.json file:");
            Console.WriteLine("   {");
            Console.WriteLine("     \"DiscordBotToken\": \"your_bot_token_here\",");
            Console.WriteLine("     \"DeveloperUserId\": \"your_discord_user_id_here\"");
            Console.WriteLine("   }");
            Console.WriteLine();
            Console.WriteLine("Note: User secrets are the most secure option for development!");
            Console.WriteLine("Note: DeveloperUserId is optional - reports will be saved to database regardless.");
            return;
        }

        Console.WriteLine("😊 Connecting to Discord...");
        
        // Start the bot
        await _client.LoginAsync(TokenType.Bot, token);
        await _client.StartAsync();

        Console.WriteLine("😄 Bot initialization complete! Press Ctrl+C to stop.");
        
        // Keep the program running
        await Task.Delay(-1);
    }

    private static async Task<bool> CheckUrlWithAntiFishApi(string url)
    {
        try
        {
            var requestData = new { message = url };
            var json = JsonConvert.SerializeObject(requestData);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");
            
            var response = await _httpClient.PostAsync(AntiFishApiUrl, content);
            
            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var result = JsonConvert.DeserializeObject<AntiFishResponse>(responseContent);
                
                if (result?.Match == true)
                {
                    Console.WriteLine($"Anti-Fish API detected scam: {url}");
                    
                    // Check if this domain is not in local database and add it
                    var domain = ExtractDomainFromUrl(url);
                    if (!await IsScamDomainAsync(url))
                    {
                        Console.WriteLine($"New scam domain detected: {domain}");
                        _ = Task.Run(() => AddScamDomainToDatabase(domain, "Anti-Fish API"));
                    }
                    
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                Console.WriteLine($"Anti-Fish API error: {response.StatusCode}");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking URL with Anti-Fish API: {ex.Message}");
            return false;
        }
    }

    private static async Task<bool> CheckDomainWithSinkingYachtsApi(string domain)
    {
        try
        {
            Console.WriteLine($"😊 Checking domain with Phish.Sinking.Yachts API: {domain}");
            
            var response = await _httpClient.GetAsync(SinkingYachtsApiUrl);
            
            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var result = JsonConvert.DeserializeObject<SinkingYachtsResponse>(responseContent);
                
                if (result?.Domains != null)
                {
                    // Normalize the domain for comparison
                    var normalizedDomain = domain.ToLowerInvariant();
                    
                    // Remove protocol if present
                    if (normalizedDomain.StartsWith("http://"))
                        normalizedDomain = normalizedDomain[7..];
                    else if (normalizedDomain.StartsWith("https://"))
                        normalizedDomain = normalizedDomain[8..];
                    else if (normalizedDomain.StartsWith("www."))
                        normalizedDomain = normalizedDomain[4..];
                    
                    // Extract domain part only
                    var domainEnd = normalizedDomain.IndexOfAny(new[] { '/', '?', '#' });
                    if (domainEnd > 0)
                        normalizedDomain = normalizedDomain[..domainEnd];
                    
                    // Check if the domain is in the phishing list
                    var isPhishing = result.Domains.Any(phishDomain => 
                        normalizedDomain.Contains(phishDomain.ToLowerInvariant()) ||
                        phishDomain.ToLowerInvariant().Contains(normalizedDomain));
                    
                    if (isPhishing)
                    {
                        Console.WriteLine($"😱 Phish.Sinking.Yachts API detected scam: {domain}");
                        
                        // Check if this domain is not in local database and add it
                        if (!await IsScamDomainAsync(domain))
                        {
                            Console.WriteLine($"😳 New scam domain detected by Phish.Sinking.Yachts: {normalizedDomain}");
                            _ = Task.Run(() => AddScamDomainToDatabase(normalizedDomain, "Phish.Sinking.Yachts"));
                        }
                        
                        return true;
                    }
                    else
                    {
                        Console.WriteLine($"😊 Phish.Sinking.Yachts API: Domain appears safe: {domain}");
                        return false;
                    }
                }
                else
                {
                    Console.WriteLine("😐 Phish.Sinking.Yachts API returned no domains data");
                    return false;
                }
            }
            else
            {
                Console.WriteLine($"😞 Phish.Sinking.Yachts API error: {response.StatusCode} {response.ReasonPhrase}");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"😞 Error checking domain with Phish.Sinking.Yachts API: {ex.Message}");
            return false;
        }
    }

    private static async Task UpdateScamDomainsFromGitHub()
    {
        try
        {
            Console.WriteLine("Fetching latest scam links from GitHub...");

            var response = await _httpClient.GetAsync(ScamLinksUrl);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                if (!string.IsNullOrWhiteSpace(content))
                {
                    await ImportDomainsFromGitHub(content);

                    var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    var domainCount = lines.Count(line => !string.IsNullOrWhiteSpace(line.Trim()) && !line.Trim().StartsWith("#"));

                    Console.WriteLine($"Successfully processed {domainCount} domains from GitHub");
                }
                else
                {
                    Console.WriteLine("GitHub response was empty, keeping existing database");
                }
            }
            else
            {
                Console.WriteLine($"Failed to fetch scam links from GitHub: {response.StatusCode}");
                Console.WriteLine("Will use existing database entries");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error while fetching scam links: {ex.Message}");
            Console.WriteLine("Will use existing database entries");
        }
    }

    private static async Task ReadyAsync()
    {
        Console.WriteLine($"{_client?.CurrentUser} is connected and ready!");
        
        // Set bot status and activity
        if (_client != null)
        {
            await _client.SetStatusAsync(UserStatus.DoNotDisturb);
            await _client.SetGameAsync($"{_client.Guilds.Count} guilds!", type: ActivityType.Watching);
            Console.WriteLine($"Bot status set to DND with activity: Watching {_client.Guilds.Count} guilds...");
        }
        
        var activeGuilds = _botSettings.Guilds.Values.Count(g => g.DefendingModeActive);
        // Use cache count for faster startup, database count will be accurate from previous load
        var domainCount = _scamDomainsCache.Count;
        Console.WriteLine($"Protection Status: {activeGuilds} guild(s) with defending mode active");
        Console.WriteLine($"Database Status: {domainCount} scam domains loaded");
        Console.WriteLine($"Protection Layers: Local Database + APIs");
        Console.WriteLine($"Startup completed at: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine("=====================================");
        
        // Register slash commands asynchronously without blocking the gateway
        _ = Task.Run(async () =>
        {
            try
            {
                // Add a small delay to ensure the bot is fully connected
                await Task.Delay(3000);
                await RegisterSlashCommands();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error registering slash commands in background: {ex.Message}");
            }
        });
    }

    private static async Task RegisterSlashCommands()
    {
        try
        {
            Console.WriteLine("Checking existing slash commands...");
            
            // Get existing commands to avoid re-registering
            var existingCommands = new List<string>();
            if (_client != null)
            {
                try
                {
                    var currentCommands = await _client.GetGlobalApplicationCommandsAsync();
                    existingCommands = currentCommands.Select(c => c.Name).ToList();
                    
                    if (existingCommands.Count > 0)
                    {
                        Console.WriteLine($"Found {existingCommands.Count} existing commands: {string.Join(", ", existingCommands)}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ Could not fetch existing commands: {ex.Message}");
                }
            }
            
            Console.WriteLine("Preparing slash commands for registration...");
            
            var commands = new List<SlashCommandBuilder>
            {
                new SlashCommandBuilder()
                    .WithName("activate")
                    .WithDescription("Activate defending mode - bot will scan messages for scam links"),
                    
                new SlashCommandBuilder()
                    .WithName("deactivate")
                    .WithDescription("Deactivate defending mode - bot will stop scanning messages"),
                    
                new SlashCommandBuilder()
                    .WithName("status")
                    .WithDescription("Check the current defending mode status"),
                    
                new SlashCommandBuilder()
                    .WithName("update")
                    .WithDescription("Manually update scam links database from GitHub"),
                    
                new SlashCommandBuilder()
                    .WithName("check")
                    .WithDescription("Check a domain for scams using three-tier validation")
                    .AddOption("domain", ApplicationCommandOptionType.String, "The domain to check (e.g., example.com)", isRequired: true),
                    
                new SlashCommandBuilder()
                    .WithName("report")
                    .WithDescription("Report a potentially malicious domain to the developers"),
                    
                new SlashCommandBuilder()
                    .WithName("whitelist")
                    .WithDescription("Manage trusted domains that should never be flagged as scams")
                    .AddOption("action", ApplicationCommandOptionType.String, "Action to perform", isRequired: true, choices: new ApplicationCommandOptionChoiceProperties[]
                    {
                        new() { Name = "add", Value = "add" },
                        new() { Name = "remove", Value = "remove" },
                        new() { Name = "list", Value = "list" }
                    })
                    .AddOption("domain", ApplicationCommandOptionType.String, "Domain to add/remove (not needed for list)", isRequired: false)
                    .AddOption("reason", ApplicationCommandOptionType.String, "Reason for whitelist action", isRequired: false),
                    
                new SlashCommandBuilder()
                    .WithName("blacklist")
                    .WithDescription("Manage domains that should be flagged as scams")
                    .AddOption("action", ApplicationCommandOptionType.String, "Action to perform", isRequired: true, choices: new ApplicationCommandOptionChoiceProperties[]
                    {
                        new() { Name = "add", Value = "add" },
                        new() { Name = "remove", Value = "remove" },
                        new() { Name = "list", Value = "list" }
                    })
                    .AddOption("domain", ApplicationCommandOptionType.String, "Domain to add/remove (not needed for list)", isRequired: false)
                    .AddOption("reason", ApplicationCommandOptionType.String, "Reason for blacklist action", isRequired: false),
                    
                new SlashCommandBuilder()
                    .WithName("stats")
                    .WithDescription("Show protection statistics for this server"),
                    
                new SlashCommandBuilder()
                    .WithName("config")
                    .WithDescription("Manage bot configuration for this server")
                    .AddOption("setting", ApplicationCommandOptionType.String, "Setting to configure", isRequired: true, choices: new ApplicationCommandOptionChoiceProperties[]
                    {
                        new() { Name = "auto_delete", Value = "auto_delete" },
                        new() { Name = "send_warnings", Value = "send_warnings" },
                        new() { Name = "log_detections", Value = "log_detections" },
                        new() { Name = "log_channel", Value = "log_channel" },
                        new() { Name = "manual_review", Value = "manual_review" },
                        new() { Name = "scam_threshold", Value = "scam_threshold" },
                        new() { Name = "show", Value = "show" }
                    })
                    .AddOption("value", ApplicationCommandOptionType.String, "New value for the setting", isRequired: false),
                    
                new SlashCommandBuilder()
                    .WithName("history")
                    .WithDescription("View domain detection history")
                    .AddOption("domain", ApplicationCommandOptionType.String, "Specific domain to check history for", isRequired: false)
                    .AddOption("days", ApplicationCommandOptionType.Integer, "Number of days to look back (default: 7)", isRequired: false)
            };

            if (_client != null)
            {
                // Filter out commands that are already registered
                var commandsToRegister = commands.Where(cmd => !existingCommands.Contains(cmd.Name)).ToList();
                
                if (commandsToRegister.Count == 0)
                {
                    Console.WriteLine("✅ All commands are already registered! No updates needed.");
                    return;
                }
                
                Console.WriteLine($"🔄 Need to register {commandsToRegister.Count} new commands (skipping {commands.Count - commandsToRegister.Count} existing)");
                
                // Register commands sequentially to avoid rate limits
                Console.WriteLine($"Registering {commandsToRegister.Count} commands with rate limit protection...");
                
                var successCount = 0;
                var failedCommands = new List<string>();
                
                for (int i = 0; i < commandsToRegister.Count; i++)
                {
                    var command = commandsToRegister[i];
                    try
                    {
                        await _client.CreateGlobalApplicationCommandAsync(command.Build());
                        successCount++;
                        Console.WriteLine($"✅ Registered command {i + 1}/{commandsToRegister.Count}: /{command.Name}");
                        
                        // Add delay between commands to respect rate limits (except for the last command)
                        if (i < commandsToRegister.Count - 1)
                        {
                            await Task.Delay(2000); // 2 second delay between each command
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"❌ Failed to register command /{command.Name}: {ex.Message}");
                        failedCommands.Add(command.Name);
                        
                        // If we hit a rate limit, wait longer before continuing
                        if (ex.Message.Contains("rate limit") || ex.Message.Contains("timed out"))
                        {
                            Console.WriteLine("⏳ Rate limit detected, waiting 5 seconds...");
                            await Task.Delay(5000);
                        }
                    }
                }
                
                if (successCount == commandsToRegister.Count)
                {
                    Console.WriteLine($"🎉 Successfully registered all {successCount} new slash commands!");
                    Console.WriteLine($"📊 Total commands available: {existingCommands.Count + successCount}");
                }
                else
                {
                    Console.WriteLine($"⚠️ Registered {successCount}/{commandsToRegister.Count} new commands successfully.");
                    if (failedCommands.Count > 0)
                    {
                        Console.WriteLine($"❌ Failed commands: {string.Join(", ", failedCommands)}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Critical error during slash command registration: {ex.Message}");
            
            // Log more details for debugging
            if (ex.InnerException != null)
                Console.WriteLine($"   Inner exception: {ex.InnerException.Message}");
            
            // Check if it's a rate limit issue
            if (ex.Message.Contains("rate limit") || ex.Message.Contains("timed out"))
            {
                Console.WriteLine("⚠️ This appears to be a rate limiting issue.");
                Console.WriteLine("💡 The bot will still work with existing commands. New commands will be available after Discord's rate limit resets.");
                Console.WriteLine("💡 To avoid this in the future, consider registering commands during off-peak hours.");
            }
            else
            {
                Console.WriteLine("⚠️ Command registration failed, but the bot will continue with existing functionality.");
            }
        }
    }

    private static async Task MessageReceivedAsync(SocketMessage message)
    {
        // Ignore messages from bots (including ourselves)
        if (message.Author.IsBot)
            return;

        // Get guild ID for this message
        var guildId = (message.Channel as SocketGuildChannel)?.Guild?.Id ?? 0;
        
        // Check if defending mode is active for this guild
        if (!IsDefendingModeActive(guildId))
            return;

        // Check if message contains URLs
        var urls = ExtractUrls(message.Content);

        if (urls.Any())
        {
            var scamUrls = new List<(string url, string source)>();
            var newDomainsDetected = new List<string>();

            foreach (var url in urls)
            {
                // Extract domain from URL for checking
                var domain = ExtractDomainFromUrl(url);
                
                // Check if domain is whitelisted first
                if (await IsWhitelistedAsync(domain, guildId))
                {
                    Console.WriteLine($"Skipping whitelisted domain: {domain}");
                    continue;
                }
                
                // First check local database (fastest)
                if (await IsScamDomainAsync(url))
                {
                    scamUrls.Add((url, "Local Database"));
                }
                else
                {
                    // If not found locally, check with both APIs as fallback
                    // Note: For real-time message scanning, we'll use a lighter approach
                    // to avoid too much delay. Full three-tier is available via /check command
                    
                    var isScamFromApi = await CheckUrlWithAntiFishApi(url);
                    if (isScamFromApi)
                    {
                        scamUrls.Add((url, "Anti-Fish API"));
                        newDomainsDetected.Add($"{domain} (Anti-Fish API)");
                    }
                    else
                    {
                        // Only check Sinking Yachts if Anti-Fish didn't detect anything
                        // This prevents excessive API calls during message scanning
                        var isSinkingYachtsScam = await CheckDomainWithSinkingYachtsApi(domain);
                        if (isSinkingYachtsScam)
                        {
                            scamUrls.Add((url, "Phish.Sinking.Yachts"));
                            newDomainsDetected.Add($"{domain} (Phish.Sinking.Yachts)");
                        }
                    }
                }
            }

            if (scamUrls.Any())
            {
                // Log newly detected domains
                if (newDomainsDetected.Any())
                {
                    Console.WriteLine($"😳 New scam domains detected and added to database:");
                    foreach (var newDomain in newDomainsDetected)
                    {
                        Console.WriteLine($"   - {newDomain}");
                    }
                    var totalCount = await GetScamDomainCountAsync();
                    Console.WriteLine($"😊 Database now contains {totalCount} active domains");
                }
                
                await HandleScamDetection(message, scamUrls);
            }
        }
    }

    private static string ExtractDomainFromUrl(string url)
    {
        try
        {
            // Normalize the URL
            var normalizedUrl = url.ToLowerInvariant();

            // Remove protocol if present
            if (normalizedUrl.StartsWith("http://"))
                normalizedUrl = normalizedUrl[7..];
            else if (normalizedUrl.StartsWith("https://"))
                normalizedUrl = normalizedUrl[8..];
            else if (normalizedUrl.StartsWith("www."))
                normalizedUrl = normalizedUrl[4..];

            // Extract domain part
            var domainEnd = normalizedUrl.IndexOfAny(new[] { '/', '?', '#' });
            if (domainEnd > 0)
                normalizedUrl = normalizedUrl[..domainEnd];

            return normalizedUrl;
        }
        catch
        {
            return url; // Return original if parsing fails
        }
    }

    private static async Task<bool> IsScamDomainAsync(string domain)
    {
        var normalizedDomain = ExtractDomainFromUrl(domain).ToLowerInvariant();
        
        // Check cache first
        if (_scamDomainsCache.ContainsKey(normalizedDomain))
            return true;

        // Check database if not in cache
        try
        {
            using var context = new NoPhishingDbContext();
            var exists = await context.ScamDomains
                .AnyAsync(d => d.IsActive && d.Domain.ToLower() == normalizedDomain);
            
            if (exists)
            {
                _scamDomainsCache[normalizedDomain] = true;
            }
            
            return exists;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"😞 Error checking domain in database: {ex.Message}");
            return false;
        }
    }

    private static async Task AddScamDomainToDatabase(string domain, string detectionSource, string? notes = null)
    {
        try
        {
            await _databaseLock.WaitAsync();
            
            var cleanDomain = ExtractDomainFromUrl(domain).ToLowerInvariant();
            
            // Check if already exists in cache
            if (_scamDomainsCache.ContainsKey(cleanDomain))
            {
                return;
            }

            using var context = new NoPhishingDbContext();
            
            // Check if domain already exists in database
            var existingDomain = await context.ScamDomains
                .FirstOrDefaultAsync(d => d.Domain.ToLower() == cleanDomain);
            
            if (existingDomain != null)
            {
                if (!existingDomain.IsActive)
                {
                    // Reactivate if it was deactivated
                    existingDomain.IsActive = true;
                    existingDomain.DateAdded = DateTime.UtcNow;
                    existingDomain.DetectionSource = detectionSource;
                    existingDomain.Notes = notes;
                    await context.SaveChangesAsync();
                    
                    _scamDomainsCache[cleanDomain] = true;
                    Console.WriteLine($"Reactivated scam domain: {cleanDomain}");
                }
                return;
            }

            // Add new domain
            var newDomain = new ScamDomain
            {
                Domain = cleanDomain,
                DetectionSource = detectionSource,
                DateAdded = DateTime.UtcNow,
                Notes = notes,
                IsActive = true
            };

            context.ScamDomains.Add(newDomain);
            await context.SaveChangesAsync();
            
            // Add to cache
            _scamDomainsCache[cleanDomain] = true;
            
            Console.WriteLine($"Added new scam domain: {cleanDomain} (detected by {detectionSource})");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error adding domain to database: {ex.Message}");
        }
        finally
        {
            _databaseLock.Release();
        }
    }

    private static async Task LoadBotSettings()
    {
        try
        {
            if (File.Exists(BotSettingsFile))
            {
                var json = await File.ReadAllTextAsync(BotSettingsFile);
                var settings = JsonConvert.DeserializeObject<BotSettings>(json);
                
                if (settings != null)
                {
                    _botSettings = settings;
                    var activeGuilds = _botSettings.Guilds.Values.Count(g => g.DefendingModeActive);
                    Console.WriteLine($"Loaded bot settings - {_botSettings.Guilds.Count} guilds, {activeGuilds} with defending mode active");
                }
                else
                {
                    Console.WriteLine("Bot settings file was empty, using defaults");
                    _botSettings = new BotSettings();
                }
            }
            else
            {
                Console.WriteLine("No bot settings file found, creating new one");
                _botSettings = new BotSettings();
                await SaveBotSettings();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading bot settings: {ex.Message}");
            _botSettings = new BotSettings();
        }
    }

    private static async Task SaveBotSettings()
    {
        try
        {
            await _settingsLock.WaitAsync();
            
            _botSettings.LastUpdated = DateTime.Now;
            var json = JsonConvert.SerializeObject(_botSettings, Formatting.Indented);
            await File.WriteAllTextAsync(BotSettingsFile, json);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error saving bot settings: {ex.Message}");
        }
        finally
        {
            _settingsLock.Release();
        }
    }

    private static bool IsDefendingModeActive(ulong guildId)
    {
        return _botSettings.Guilds.TryGetValue(guildId, out var settings) && settings.DefendingModeActive;
    }

    private static async Task SetDefendingMode(ulong guildId, bool active, string? activatedBy = null)
    {
        if (!_botSettings.Guilds.TryGetValue(guildId, out var settings))
        {
            settings = new GuildSettings { GuildId = guildId };
            _botSettings.Guilds[guildId] = settings;
        }

        settings.DefendingModeActive = active;
        settings.LastActivated = DateTime.Now;
        settings.ActivatedBy = activatedBy;

        await SaveBotSettings();
    }

    // Database methods
    private static async Task InitializeDatabase()
    {
        try
        {
            using var context = new NoPhishingDbContext();
            
            // Check if database needs to be recreated (for schema updates)
            bool needsRecreation = false;
            
            try
            {
                // Try to access the new tables to see if they exist
                await context.DomainReports.CountAsync();
                await context.WhitelistDomains.CountAsync();
                await context.ServerConfigs.CountAsync();
                await context.DetectionLogs.CountAsync();
            }
            catch (Exception)
            {
                // New tables don't exist, need to recreate database
                needsRecreation = true;
                Console.WriteLine("😊 New database schema detected, updating database...");
            }
            
            if (needsRecreation)
            {
                // Backup existing data if database exists
                List<ScamDomain>? existingDomains = null;
                List<DomainImportLog>? existingLogs = null;
                
                try
                {
                    existingDomains = await context.ScamDomains.ToListAsync();
                    existingLogs = await context.DomainImportLogs.ToListAsync();
                    Console.WriteLine($"😊 Backed up {existingDomains.Count} domains and {existingLogs.Count} import logs");
                }
                catch (Exception)
                {
                    // Old tables might not exist, that's ok
                    Console.WriteLine("😊 No existing data to backup (fresh installation)");
                }
                
                // Delete and recreate database
                await context.Database.EnsureDeletedAsync();
                await context.Database.EnsureCreatedAsync();
                
                // Restore data if we had any
                if (existingDomains?.Count > 0)
                {
                    context.ScamDomains.AddRange(existingDomains);
                    Console.WriteLine($"😊 Restored {existingDomains.Count} scam domains");
                }
                
                if (existingLogs?.Count > 0)
                {
                    context.DomainImportLogs.AddRange(existingLogs);
                    Console.WriteLine($"😊 Restored {existingLogs.Count} import logs");
                }
                
                if ((existingDomains?.Count > 0) || (existingLogs?.Count > 0))
                {
                    await context.SaveChangesAsync();
                    Console.WriteLine("😊 Database migration completed successfully");
                }
            }
            else
            {
                // Just ensure database exists
                await context.Database.EnsureCreatedAsync();
            }
            
            Console.WriteLine("Database initialized successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error initializing database: {ex.Message}");
            throw;
        }
    }

    private static async Task LoadScamDomainsFromDatabase()
    {
        try
        {
            using var context = new NoPhishingDbContext();
            var domains = await context.ScamDomains
                .Where(d => d.IsActive)
                .Select(d => d.Domain.ToLower())
                .ToListAsync();

            _scamDomainsCache.Clear();
            foreach (var domain in domains)
            {
                _scamDomainsCache[domain] = true;
            }

            Console.WriteLine($"Loaded {domains.Count} scam domains from database");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading scam domains from database: {ex.Message}");
            throw;
        }
    }

    private static async Task<int> GetScamDomainCountAsync()
    {
        try
        {
            using var context = new NoPhishingDbContext();
            return await context.ScamDomains.CountAsync(d => d.IsActive);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error getting domain count: {ex.Message}");
            return _scamDomainsCache.Count;
        }
    }


    private static async Task ImportDomainsFromGitHub(string content)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(content))
                return;

            Console.WriteLine("😊 Importing domains from GitHub to database...");
            
            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var importedCount = 0;
            var skippedCount = 0;
            const int batchSize = 1000;

            using var context = new NoPhishingDbContext();
            
            // Get existing domains to avoid checking each one individually
            var existingDomains = await context.ScamDomains
                .Where(d => d.IsActive)
                .Select(d => d.Domain.ToLower())
                .ToHashSetAsync();
            
            // Process and deduplicate domains from GitHub
            var uniqueDomainsFromGitHub = new HashSet<string>();
            
            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();
                
                if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith("#"))
                {
                    skippedCount++;
                    continue;
                }

                var normalizedDomain = trimmedLine.ToLowerInvariant();
                uniqueDomainsFromGitHub.Add(normalizedDomain);
            }
            
            var domainsToAdd = new List<ScamDomain>();
            
            foreach (var normalizedDomain in uniqueDomainsFromGitHub)
            {
                if (!existingDomains.Contains(normalizedDomain))
                {
                    var newDomain = new ScamDomain
                    {
                        Domain = normalizedDomain,
                        DetectionSource = "GitHub Repository",
                        DateAdded = DateTime.UtcNow,
                        Notes = "Imported from Discord-AntiScam repository",
                        IsActive = true
                    };

                    domainsToAdd.Add(newDomain);
                    _scamDomainsCache[normalizedDomain] = true;
                    importedCount++;

                    // Save in batches to avoid Entity Framework limits
                    if (domainsToAdd.Count >= batchSize)
                    {
                        await context.ScamDomains.AddRangeAsync(domainsToAdd);
                        await context.SaveChangesAsync();
                        context.ChangeTracker.Clear();
                        domainsToAdd.Clear();
                    }
                }
                else
                {
                    skippedCount++;
                }
            }

            // Save any remaining domains
            if (domainsToAdd.Count > 0)
            {
                await context.ScamDomains.AddRangeAsync(domainsToAdd);
                await context.SaveChangesAsync();
            }

            // Log the import
            if (importedCount > 0)
            {
                var importLog = new DomainImportLog
                {
                    Source = "Discord-AntiScam GitHub",
                    ImportDate = DateTime.UtcNow,
                    DomainsImported = importedCount,
                    DomainsSkipped = skippedCount,
                    Notes = "Automated import from GitHub repository"
                };
                
                context.DomainImportLogs.Add(importLog);
                await context.SaveChangesAsync();
            }

            var totalFromGitHub = uniqueDomainsFromGitHub.Count;
            Console.WriteLine($"😄 GitHub import complete: {importedCount} new domains imported, {skippedCount} already existed (processed {totalFromGitHub} unique domains from GitHub)");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"😞 Error importing domains from GitHub: {ex.Message}");
            if (ex.InnerException != null)
                Console.WriteLine($"   Inner exception: {ex.InnerException.Message}");
            Console.WriteLine($"   Stack trace: {ex.StackTrace}");
        }
    }

    private static List<string> ExtractUrls(string messageContent)
    {
        var urls = new List<string>();
        var regex = new Regex(@"https?://[^\s]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        var matches = regex.Matches(messageContent);

        foreach (Match match in matches)
        {
            urls.Add(match.Value);
        }

        return urls;
    }

    private static async Task HandleScamDetection(SocketMessage message, List<(string url, string source)> scamUrls)
    {
        try
        {
            // Create an embed with scam warning (without showing the URLs directly)
            var embed = new EmbedBuilder()
                .WithColor(Color.Red)
                .WithTitle("🚨 SCAM LINK DETECTED 🚨")
                .WithDescription($"**Warning**: The message from {message.Author.Mention} contains {scamUrls.Count} potentially malicious link{(scamUrls.Count > 1 ? "s" : "")}!")
                .AddField("Detection Sources", string.Join(", ", scamUrls.Select(s => s.source).Distinct()), true)
                .AddField("⚠️ Do NOT click these links!", "These URLs have been identified as potential scams or phishing attempts.", false)
                .AddField("🔒 Safety Note", "Click the button below to reveal the URLs if needed for investigation purposes.", false)
                .AddField("🛡️ Protection Level", "Three-Tier Validation + Auto-Learning", true)
                .AddField("🧠 Smart Database", "New threats automatically added", true)
                .WithFooter("NoPhishing Bot - Stay Safe!")
                .WithTimestamp(DateTimeOffset.Now)
                .Build();

            // Create a button to reveal the scam URLs
            var customId = $"reveal_scam_{Guid.NewGuid():N}";
            var button = new ButtonBuilder()
                .WithLabel("👁️ Reveal Scam URLs")
                .WithStyle(ButtonStyle.Danger)
                .WithCustomId(customId);

            var component = new ComponentBuilder()
                .WithButton(button);

            // Store the scam URLs for this button interaction
            _pendingScamReveals[customId] = scamUrls;

            // Send warning message with button
            await message.Channel.SendMessageAsync(embed: embed, components: component.Build());

            // Log the detection to database
            await LogDetectionToDatabase(message, scamUrls);

            // Log the detection
            Console.WriteLine($"Scam link detected in message from {message.Author.Username} ({message.Author.Id}):");
            foreach (var (url, source) in scamUrls)
            {
                Console.WriteLine($"  - {url} (detected by: {source})");
            }

            await message.DeleteAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error handling scam detection: {ex.Message}");
        }
    }

    private static async Task ButtonExecutedAsync(SocketMessageComponent component)
    {
        try
        {
            var customId = component.Data.CustomId;
            
            if (customId.StartsWith("reveal_scam_") && _pendingScamReveals.TryGetValue(customId, out var scamUrls))
            {
                // Create an ephemeral response showing the scam URLs
                var urlsWithSources = scamUrls.Select(item => $"🔗 `{item.url}` (detected by: {item.source})");
                
                var revealEmbed = new EmbedBuilder()
                    .WithColor(Color.Red)
                    .WithTitle("🔍 Revealed Scam URLs")
                    .WithDescription("⚠️ **WARNING**: These are potentially malicious URLs. Do NOT click them!")
                    .AddField("Detected Scam URLs", string.Join("\n", urlsWithSources))
                    .AddField("🛡️ Safety Reminder", "These URLs were flagged by our protection systems. Avoid clicking them to stay safe.", false)
                    .AddField("Investigation Tip", "Use a safe environment to analyze these URLs, if necessary.", false)
                    .WithFooter("NoPhishing Bot - For Investigation Purposes Only")
                    .WithTimestamp(DateTimeOffset.Now)
                    .Build();

                await component.RespondAsync(embed: revealEmbed, ephemeral: true);
                
                // Clean up the stored data after a delay to prevent memory leaks
                _ = Task.Delay(TimeSpan.FromMinutes(10)).ContinueWith(_ => 
                {
                    _pendingScamReveals.TryRemove(customId, out var _);
                });
                
                Console.WriteLine($"Scam URLs revealed to {component.User.Username} ({component.User.Id})");
            }
            else
            {
                await component.RespondAsync("This reveal request has expired or is invalid.", ephemeral: true);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error handling button interaction: {ex.Message}");
            try
            {
                await component.RespondAsync("An error occurred while processing the button click.", ephemeral: true);
            }
            catch
            {
                // Ignore if we can't respond
            }
        }
    }

    private static async Task SlashCommandHandler(SocketSlashCommand command)
    {
        try
        {
            var guildId = command.GuildId ?? 0;
            
            // Check if command is being used in a guild (server) and not in DMs
            if (guildId == 0)
            {
                var dmEmbed = new EmbedBuilder()
                    .WithColor(Color.Red)
                    .WithTitle("❌ Guild Required")
                    .WithDescription("This bot's commands can only be used in Discord servers, not in direct messages.")
                    .AddField("🏠 How to Use", "Invite the bot to your Discord server and use the commands there.", false)
                    .AddField("🛡️ Why This Restriction?", "The bot manages server-specific protection settings that don't apply to DMs.", false)
                    .AddField("📋 Available Commands", "`/activate`, `/deactivate`, `/status`, `/update`, `/check`, `/report`, `/whitelist`, `/blacklist`, `/stats`, `/config`, `/history`", false)
                    .WithFooter("NoPhishing Bot - Server Protection")
                    .WithTimestamp(DateTimeOffset.Now)
                    .Build();
                    
                await command.RespondAsync(embed: dmEmbed, ephemeral: true);
                Console.WriteLine($"Command '{command.Data.Name}' blocked - attempted use in DM by {command.User.Username} ({command.User.Id})");
                return;
            }
            
            switch (command.Data.Name)
            {
                case "activate":
                    await SetDefendingMode(guildId, true, command.User.Username);
                    var activatedEmbed = new EmbedBuilder()
                        .WithColor(Color.Green)
                        .WithTitle("✅ Defending Mode Activated")
                        .WithDescription("The bot is now actively scanning messages for scam links using three-tier validation!")
                        .AddField("Guild Protection", "🛡️ Active", true)
                        .AddField("Protection Layers", "Database + APIs", true)
                        .AddField("Persistence", "💾 Survives bot restarts", true)
                        .WithFooter("NoPhishing Bot - Stay Safe!")
                        .WithTimestamp(DateTimeOffset.Now)
                        .Build();
                    await command.RespondAsync(embed: activatedEmbed);
                    Console.WriteLine($"Defending mode activated by {command.User.Username} in guild {guildId}");
                    break;

                case "deactivate":
                    await SetDefendingMode(guildId, false, command.User.Username);
                    var deactivatedEmbed = new EmbedBuilder()
                        .WithColor(Color.Red)
                        .WithTitle("❌ Defending Mode Deactivated")
                        .WithDescription("The bot has stopped scanning messages for scam links in this server.")
                        .AddField("Guild Protection", "🔒 Inactive", true)
                        .AddField("Persistence", "💾 Setting saved", true)
                        .WithFooter("NoPhishing Bot")
                        .WithTimestamp(DateTimeOffset.Now)
                        .Build();
                    await command.RespondAsync(embed: deactivatedEmbed);
                    Console.WriteLine($"Defending mode deactivated by {command.User.Username} in guild {guildId}");
                    break;

                case "status":
                    var isActive = IsDefendingModeActive(guildId);
                    var statusColor = isActive ? Color.Green : Color.Red;
                    var statusIcon = isActive ? "🛡️" : "🔒";
                    var statusText = isActive ? "Active" : "Inactive";
                    
                    var guildSettings = _botSettings.Guilds.TryGetValue(guildId, out var settings) ? settings : null;
                    var lastActivated = guildSettings?.LastActivated.ToString("yyyy-MM-dd HH:mm") ?? "Never";
                    var activatedBy = guildSettings?.ActivatedBy ?? "Unknown";
                    var domainCount = await GetScamDomainCountAsync();
                    
                    var statusEmbed = new EmbedBuilder()
                        .WithColor(statusColor)
                        .WithTitle("📊 NoPhishing Bot Status")
                        .AddField("Defending Mode", $"{statusIcon} {statusText}", true)
                        .AddField("Guild ID", guildId.ToString(), true)
                        .AddField("Scam Domains", $"{domainCount} in database", true)
                        .AddField("Protection Layers", "Database + Phish.Sinking.Yachts + Anti-Fish API", true)
                        .AddField("Auto-Learning", "🧠 Enabled - New domains auto-added", true)
                        .AddField("Persistence", "💾 Settings survive restarts", true)
                        .AddField("Last Activated", lastActivated, true)
                        .AddField("Activated By", activatedBy, true)
                        .AddField("Database Type", "SQLite + In-Memory Cache", true)
                        .WithFooter("NoPhishing Bot")
                        .WithTimestamp(DateTimeOffset.Now)
                        .Build();
                    await command.RespondAsync(embed: statusEmbed, ephemeral: true);
                    break;

                case "update":
                    // Check if user is the bot owner
                    var devUserIdString = _configuration?["DeveloperUserId"];
                    if (string.IsNullOrEmpty(devUserIdString) || !ulong.TryParse(devUserIdString, out var devUserId) || command.User.Id != devUserId)
                    {
                        var notOwnerEmbed = new EmbedBuilder()
                            .WithColor(Color.Red)
                            .WithTitle("🔒 Owner Only Command")
                            .WithDescription("The `/update` command can only be used by the bot owner.")
                            .AddField("🛡️ Security", "This restriction prevents unauthorized database updates.", false)
                            .AddField("📝 Note", "If you are the bot owner, ensure your Discord user ID is properly configured.", false)
                            .WithFooter("NoPhishing Bot - Access Denied")
                            .WithTimestamp(DateTimeOffset.Now)
                            .Build();
                        
                        await command.RespondAsync(embed: notOwnerEmbed, ephemeral: true);
                        Console.WriteLine($"Update command blocked - unauthorized user: {command.User.Username} ({command.User.Id})");
                        return;
                    }
                    
                    await command.RespondAsync("🔄 Updating scam domains database from GitHub...", ephemeral: true);
                    
                    var previousCount = await GetScamDomainCountAsync();
                    var updateStartTime = DateTime.Now;
                    
                    await UpdateScamDomainsFromGitHub();
                    await LoadScamDomainsFromDatabase();
                    
                    var newCount = await GetScamDomainCountAsync();
                    var difference = newCount - previousCount;
                    var differenceText = difference switch
                    {
                        > 0 => $"+{difference} domains added",
                        < 0 => $"{Math.Abs(difference)} domains removed", 
                        0 => "No changes"
                    };
                    
                    var updateEmbed = new EmbedBuilder()
                        .WithColor(Color.Blue)
                        .WithTitle("🔄 Database Update Complete")
                        .WithDescription("Successfully updated scam domains database from GitHub!")
                        .AddField("Previous Count", previousCount.ToString(), true)
                        .AddField("New Count", newCount.ToString(), true)
                        .AddField("Changes", differenceText, true)
                        .AddField("Update Duration", $"{(DateTime.Now - updateStartTime).TotalSeconds:F1}s", true)
                        .AddField("Source", "[Discord-AntiScam Repository](https://github.com/Discord-AntiScam/scam-links)", false)
                        .AddField("Storage", "SQLite Database + Cache", true)
                        .WithFooter("NoPhishing Bot - Database Updated")
                        .WithTimestamp(DateTimeOffset.Now)
                        .Build();
                    
                    await command.ModifyOriginalResponseAsync(msg => 
                    {
                        msg.Content = "";
                        msg.Embed = updateEmbed;
                    });
                    
                    Console.WriteLine($"Manual database update completed by {command.User.Username} ({command.User.Id})");
                    Console.WriteLine($"Database changed from {previousCount} to {newCount} domains ({differenceText})");
                    break;

                case "check":
                    if (command.Data.Options?.Count > 0)
                    {
                        var domain = command.Data.Options.First().Value?.ToString();
                        if (!string.IsNullOrEmpty(domain))
                        {
                            await command.RespondAsync($"🔍 Starting three-tier domain check for: `{domain}`...", ephemeral: true);
                            
                            // Perform comprehensive three-tier check
                            var checkResult = await PerformThreeTierDomainCheck(domain);
                            
                            // Determine embed color and title based on result
                            var embedColor = checkResult.IsScam ? Color.Red : Color.Green;
                            var embedTitle = checkResult.IsScam ? "🚨 MALICIOUS DOMAIN DETECTED" : "✅ Domain Check Complete";
                            var embedDescription = checkResult.IsScam 
                                ? $"**WARNING**: `{domain}` has been flagged as potentially malicious!"
                                : $"Domain `{domain}` appears to be safe based on all available checks.";
                            

                            // Create detailed results
                            var detectionInfo = checkResult.DetectionSources.Count > 0 
                                ? string.Join(", ", checkResult.DetectionSources)
                                : "None";
                            

                            var detailsText = string.Join("\n", checkResult.Details.Select(d => $"🔹 {d}"));
                            

                            var recommendation = checkResult.IsScam 
                                ? "⚠️ **DO NOT VISIT** this domain! It has been identified as malicious."
                                : "✅ This domain appears safe to visit based on current threat intelligence.";
                            

                            var checkEmbed = new EmbedBuilder()
                                .WithColor(embedColor)
                                .WithTitle(embedTitle)
                                .WithDescription(embedDescription)
                                .AddField("Domain Checked", $"`{domain}`", false)
                                .AddField("Detection Sources", detectionInfo, true)
                                .AddField("Threat Level", checkResult.IsScam ? "🔴 HIGH RISK" : "🟢 LOW RISK", true)
                                .AddField("Check Details", detailsText, false)
                                .AddField("Recommendation", recommendation, false)
                                .AddField("Validation Method", "Three-Tier Analysis", true)
                                .AddField("Sources Used", "Database + Phish.Sinking.Yachts + Anti-Fish API", true)
                                .WithFooter("NoPhishing Bot - Three-Tier Domain Analysis")
                                .WithTimestamp(DateTimeOffset.Now)
                                .Build();
                            
                            await command.ModifyOriginalResponseAsync(msg => 
                            {
                                msg.Content = "";
                                msg.Embed = checkEmbed;
                            });
                            
                            // Console logging
                            var sources = checkResult.DetectionSources.Count > 0 
                                ? string.Join(", ", checkResult.DetectionSources) 
                                : "None";
                            Console.WriteLine($"Three-tier domain check by {command.User.Username} for {domain}: {(checkResult.IsScam ? "MALICIOUS" : "SAFE")} (sources: {sources})");
                        }
                        else
                        {
                            await command.RespondAsync("❌ Please provide a valid domain to check (e.g., example.com).", ephemeral: true);
                        }
                    }
                    else
                    {
                        await command.RespondAsync("❌ Please provide a domain to check. Usage: `/check domain:example.com`", ephemeral: true);
                    }
                    break;

                case "report":
                    // Create a modal form for reporting domains
                    var reportModal = new ModalBuilder()
                        .WithTitle("🚨 Report Malicious Domain")
                        .WithCustomId("domain_report_modal")
                        .AddTextInput("Domain to Report", "report_domain", TextInputStyle.Short, 
                            placeholder: "example.com or https://suspicious-site.com", 
                            required: true, 
                            maxLength: 200)
                        .AddTextInput("Reason for Reporting", "report_reason", TextInputStyle.Paragraph, 
                            placeholder: "Describe why you think this domain is malicious (phishing, scam, malware, etc.)", 
                            required: false, 
                            maxLength: 1000)
                        .AddTextInput("Additional Details", "report_details", TextInputStyle.Paragraph, 
                            placeholder: "Any additional information that might help (optional)", 
                            required: false, 
                            maxLength: 500);

                    await command.RespondWithModalAsync(reportModal.Build());
                    Console.WriteLine($"Report modal shown to {command.User.Username} ({command.User.Id})");
                    break;

                case "whitelist":
                    await HandleWhitelistCommand(command);
                    break;

                case "blacklist":
                    await HandleBlacklistCommand(command);
                    break;

                case "stats":
                    await HandleStatsCommand(command);
                    break;

                case "config":
                    await HandleConfigCommand(command);
                    break;

                case "history":
                    await HandleHistoryCommand(command);
                    break;

                default:
                    await command.RespondAsync("❓ Unknown command.", ephemeral: true);
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error handling slash command: {ex.Message}");
            try
            {
                await command.RespondAsync("An error occurred while processing the command.", ephemeral: true);
            }
            catch
            {
                // Ignore if we can't respond
            }
        }
    }

    private static async Task<DomainCheckResult> PerformThreeTierDomainCheck(string domain)
    {
        var result = new DomainCheckResult
        {
            Domain = domain,
            IsScam = false,
            DetectionSources = new List<string>(),
            Details = new List<string>()
        };

        Console.WriteLine($"😊 Starting three-tier domain check for: {domain}");
        var newlyDetectedSources = new List<string>();

        // Tier 1: Database Check
        Console.WriteLine("😊 Tier 1: Checking database...");
        var isLocalScam = await IsScamDomainAsync(domain);
        if (isLocalScam)
        {
            result.IsScam = true;
            result.DetectionSources.Add("Database");
            var domainCount = await GetScamDomainCountAsync();
            result.Details.Add($"Found in local database ({domainCount} domains)");
            Console.WriteLine("😱 Tier 1: DETECTED - Domain found in database");
        }
        else
        {
            result.Details.Add("Not found in local database");
            Console.WriteLine("😊 Tier 1: CLEAN - Domain not in database");
        }

        // Tier 2: Phish.Sinking.Yachts API Check
        Console.WriteLine("😊 Tier 2: Checking with Phish.Sinking.Yachts API...");
        try
        {
            var isSinkingYachtsScam = await CheckDomainWithSinkingYachtsApi(domain);
            if (isSinkingYachtsScam)
            {
                result.IsScam = true;
                result.DetectionSources.Add("Phish.Sinking.Yachts");
                result.Details.Add("Flagged by Phish.Sinking.Yachts community database");
                Console.WriteLine("😱 Tier 2: DETECTED - Domain flagged by Phish.Sinking.Yachts");
                
                if (!isLocalScam)
                {
                    newlyDetectedSources.Add("Phish.Sinking.Yachts");
                }
            }
            else
            {
                result.Details.Add("Not flagged by Phish.Sinking.Yachts API");
                Console.WriteLine("😊 Tier 2: CLEAN - Domain not flagged by Phish.Sinking.Yachts");
            }
        }
        catch (Exception ex)
        {
            result.Details.Add($"Phish.Sinking.Yachts API error: {ex.Message}");
            Console.WriteLine($"😞 Tier 2: ERROR - {ex.Message}");
        }

        // Tier 3: Anti-Fish API Check
        Console.WriteLine("😊 Tier 3: Checking with Anti-Fish API...");
        try
        {
            var isAntiFishScam = await CheckUrlWithAntiFishApi(domain);
            if (isAntiFishScam)
            {
                result.IsScam = true;
                result.DetectionSources.Add("Anti-Fish API");
                result.Details.Add("Detected by Anti-Fish real-time analysis");
                Console.WriteLine("😱 Tier 3: DETECTED - Domain flagged by Anti-Fish API");
                
                if (!isLocalScam)
                {
                    newlyDetectedSources.Add("Anti-Fish API");
                }
            }
            else
            {
                result.Details.Add("Not detected by Anti-Fish API");
                Console.WriteLine("😊 Tier 3: CLEAN - Domain not flagged by Anti-Fish API");
            }
        }
        catch (Exception ex)
        {
            result.Details.Add($"Anti-Fish API error: {ex.Message}");
            Console.WriteLine($"😞 Tier 3: ERROR - {ex.Message}");
        }

        // Add information about newly added domains
        if (newlyDetectedSources.Any())
        {
            var sourcesText = string.Join(" + ", newlyDetectedSources);
            result.Details.Add($"🤓 Domain automatically added to database (detected by: {sourcesText})");
            Console.WriteLine($"🤓 Domain {domain} added to database from external detection");
        }

        // Summary
        var finalStatus = result.IsScam ? "MALICIOUS" : "SAFE";
        var sourceCount = result.DetectionSources.Count;
        Console.WriteLine($"😄 Three-tier check complete: {finalStatus} (detected by {sourceCount} source{(sourceCount != 1 ? "s" : "")})");

        return result;
    }

    private static async Task<(bool success, string message)> SendDomainReport(string domain, string? reason, SocketUser user, SocketGuild? guild)
    {
        try
        {
            Console.WriteLine($"😊 Processing domain report for: {domain} by {user.Username}");
            
            // Clean and normalize the domain
            var cleanDomain = ExtractDomainFromUrl(domain).ToLowerInvariant();
            
            // Save report to database
            using var context = new NoPhishingDbContext();
            
            // Ensure the database schema is up to date (in case DomainReports table doesn't exist)
            try
            {
                await context.Database.EnsureCreatedAsync();
            }
            catch (Exception dbEx)
            {
                Console.WriteLine($"😞 Database schema update failed: {dbEx.Message}");
                // Continue anyway, might still work
            }
            
            var report = new DomainReport
            {
                Domain = cleanDomain,
                Reason = reason,
                ReportedByUserId = user.Id,
                ReportedByUsername = user.Username,
                GuildId = guild?.Id,
                GuildName = guild?.Name,
                ReportDate = DateTime.UtcNow,
                IsProcessed = false
            };
            
            context.DomainReports.Add(report);
            await context.SaveChangesAsync();
            
            // Try to send report to developer (you can configure this)
            bool sentTodev = await TrySendReportToDeveloper(cleanDomain, reason, user, guild);
            
            Console.WriteLine($"😄 Domain report saved to database. Developer notification: {(sentTodev ? "Sent" : "Failed")}");
            
            return (true, "Report saved successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"😞 Error processing domain report: {ex.Message}");
            if (ex.InnerException != null)
            {
                Console.WriteLine($"😞 Inner exception: {ex.InnerException.Message}");
            }
            
            // If database save fails, still try to send the report to developer
            try
            {
                Console.WriteLine("😊 Attempting to send report to developer despite database error...");
                bool sentTodev = await TrySendReportToDeveloper(domain, reason, user, guild);
                
                if (sentTodev)
                {
                    return (false, "Database error occurred, but report was sent to developer via DM");
                }
                else
                {
                    return (false, "Both database save and developer notification failed");
                }
            }
            catch (Exception fallbackEx)
            {
                Console.WriteLine($"😞 Fallback developer notification also failed: {fallbackEx.Message}");
                return (false, $"Complete failure: {ex.Message}");
            }
        }
    }

    private static async Task<bool> TrySendReportToDeveloper(string domain, string? reason, SocketUser user, SocketGuild? guild)
    {
        try
        {
            // Get developer user ID from configuration
            var devUserIdString = _configuration?["DeveloperUserId"];
            
            Console.WriteLine($"🔍 Debug: DeveloperUserId from config: '{devUserIdString}'");
            
            if (string.IsNullOrEmpty(devUserIdString) || !ulong.TryParse(devUserIdString, out var devUserId))
            {
                Console.WriteLine("😐 Developer user ID not configured or invalid. Report saved to database only.");
                Console.WriteLine("💡 To enable DM notifications, set your Discord user ID:");
                Console.WriteLine("   dotnet user-secrets set \"DeveloperUserId\" \"YOUR_DISCORD_USER_ID\"");
                Console.WriteLine("   (To get your user ID: Enable Developer Mode in Discord, right-click your name, Copy User ID)");
                return false;
            }
            
            Console.WriteLine($"🔍 Debug: Parsed developer user ID: {devUserId}");
            
            // Try to get the developer user
            var devUser = _client?.GetUser(devUserId);
            if (devUser == null)
            {
                Console.WriteLine($"😞 Could not find developer user with ID: {devUserId}");
                Console.WriteLine("💡 Make sure:");
                Console.WriteLine("   1. The user ID is correct");
                Console.WriteLine("   2. The bot shares at least one server with you");
                Console.WriteLine("   3. You haven't blocked the bot");
                return false;
            }
            
            Console.WriteLine($"🔍 Debug: Found developer user: {devUser.Username}#{devUser.Discriminator}");
            
            // Create report embed for developer
            var reportEmbed = new EmbedBuilder()
                .WithColor(Color.Orange)
                .WithTitle("🚨 New Domain Report")
                .WithDescription($"A user has reported a potentially malicious domain!")
                .AddField("Reported Domain", $"`{domain}`", true)
                .AddField("Report ID", $"`{DateTime.UtcNow.Ticks:X}`", true)
                .AddField("Reported By", $"{user.Username} ({user.Id})", true)
                .AddField("Guild", guild != null ? $"{guild.Name} ({guild.Id})" : "Direct Message", true)
                .AddField("Reason", string.IsNullOrEmpty(reason) ? "Not specified" : reason, false)
                .AddField("Report Time", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"), true)
                .AddField("🔍 Actions Available", "• Check domain with `/check`\n• Review in database\n• Add to scam list if confirmed", false)
                .WithFooter("NoPhishing Bot - Domain Report System")
                .WithTimestamp(DateTimeOffset.Now)
                .Build();
            
            Console.WriteLine($"🔍 Debug: Creating DM channel with {devUser.Username}...");
            
            // Send DM to developer
            var dmChannel = await devUser.CreateDMChannelAsync();
            await dmChannel.SendMessageAsync(embed: reportEmbed);
            
            Console.WriteLine($"😄 Report sent to developer {devUser.Username} via DM successfully!");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"😞 Failed to send report to developer: {ex.Message}");
            Console.WriteLine($"😞 Stack trace: {ex.StackTrace}");
            return false;
        }
    }

    private static async Task ModalSubmittedAsync(SocketModal modal)
    {
        try
        {
            // Check if modal is being submitted in a guild (server) and not in DMs
            var guildId = modal.GuildId ?? 0;
            if (guildId == 0)
            {
                var dmEmbed = new EmbedBuilder()
                    .WithColor(Color.Red)
                    .WithTitle("❌ Guild Required")
                    .WithDescription("Report submissions can only be made from Discord servers, not from direct messages.")
                    .AddField("🏠 How to Use", "Use the `/report` command in a Discord server where the bot is present.", false)
                    .AddField("🛡️ Security Note", "This restriction helps maintain proper reporting context and security.", false)
                    .WithFooter("NoPhishing Bot - Server Protection")
                    .WithTimestamp(DateTimeOffset.Now)
                    .Build();
                    
                await modal.RespondAsync(embed: dmEmbed, ephemeral: true);
                Console.WriteLine($"Report modal blocked - attempted submission in DM by {modal.User.Username} ({modal.User.Id})");
                return;
            }
            
            if (modal.Data.CustomId == "domain_report_modal")
            {
                // Extract form data
                var domainInput = modal.Data.Components.FirstOrDefault(c => c.CustomId == "report_domain");
                var reasonInput = modal.Data.Components.FirstOrDefault(c => c.CustomId == "report_reason");
                var detailsInput = modal.Data.Components.FirstOrDefault(c => c.CustomId == "report_details");

                var reportedDomain = domainInput?.Value?.Trim();
                var reason = reasonInput?.Value?.Trim();
                var additionalDetails = detailsInput?.Value?.Trim();

                if (string.IsNullOrEmpty(reportedDomain))
                {
                    await modal.RespondAsync("❌ Domain field cannot be empty. Please try again.", ephemeral: true);
                    return;
                }

                // Normalize domain (remove protocol if present)
                var cleanDomain = ExtractDomainFromUrl(reportedDomain);

                await modal.RespondAsync($"📝 Submitting report for domain: `{cleanDomain}`...", ephemeral: true);

                // Combine reason and additional details
                var fullReason = reason;
                if (!string.IsNullOrEmpty(additionalDetails))
                {
                    fullReason = string.IsNullOrEmpty(fullReason) 
                        ? additionalDetails 
                        : $"{fullReason}\n\nAdditional Details: {additionalDetails}";
                }

                // Send report to developer
                var guild = _client?.GetGuild(modal.GuildId ?? 0);
                var reportResult = await SendDomainReport(cleanDomain, fullReason, modal.User, guild);

                // Create detailed response embed
                var reportEmbed = new EmbedBuilder()
                    .WithColor(reportResult.success ? Color.Green : Color.Orange)
                    .WithTitle(reportResult.success ? "✅ Report Submitted Successfully" : "⚠️ Report Submitted (Partial)")
                    .WithDescription($"Thank you for reporting `{cleanDomain}`. Your report helps keep the community safe!")
                    .AddField("📝 Reported Domain", $"`{cleanDomain}`", true)
                    .AddField("🆔 Report ID", $"`{DateTime.UtcNow.Ticks:X}`", true)
                    .AddField("📊 Status", reportResult.success ? "📧 Sent to developer" : "📄 Logged locally", true)
                    .AddField("📋 Report Summary", 
                        $"**Reason:** {(string.IsNullOrEmpty(reason) ? "Not specified" : reason)}\n" +
                        (string.IsNullOrEmpty(additionalDetails) ? "" : $"**Additional Details:** {additionalDetails}"), false)
                    .AddField("🔄 Next Steps", "The development team will review your report and take appropriate action if necessary.", false)
                    .AddField("💡 Pro Tip", "Use `/check domain:example.com` to verify if a domain is already known to be malicious.", false)
                    .WithFooter($"Reported by {modal.User.Username} • Thank you for helping keep the community safe!")
                    .WithTimestamp(DateTimeOffset.Now)
                    .Build();

                await modal.ModifyOriginalResponseAsync(msg => 
                {
                    msg.Content = "";
                    msg.Embed = reportEmbed;
                });

                // Console logging
                Console.WriteLine($"📝 Domain report submitted via modal by {modal.User.Username} ({modal.User.Id}):");
                Console.WriteLine($"   Domain: {cleanDomain}");
                if (!string.IsNullOrEmpty(reason))
                    Console.WriteLine($"   Reason: {reason}");
                if (!string.IsNullOrEmpty(additionalDetails))
                    Console.WriteLine($"   Additional Details: {additionalDetails}");
                Console.WriteLine($"   Report Status: {(reportResult.success ? "Sent to developer" : "Logged locally only")}");
            }
            else
            {
                await modal.RespondAsync("❓ Unknown modal form.", ephemeral: true);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error handling modal submission: {ex.Message}");
            try
            {
                await modal.RespondAsync("An error occurred while processing your report. Please try again later.", ephemeral: true);
            }
            catch
            {
                // Ignore if we can't respond
            }
        }
    }

    private static Task LogAsync(LogMessage log)
    {
        Console.WriteLine(log.ToString());
        return Task.CompletedTask;
    }

    private static async Task HandleWhitelistCommand(SocketSlashCommand command)
    {
        try
        {
            var action = command.Data.Options?.FirstOrDefault(x => x.Name == "action")?.Value?.ToString();
            var domain = command.Data.Options?.FirstOrDefault(x => x.Name == "domain")?.Value?.ToString();
            var reason = command.Data.Options?.FirstOrDefault(x => x.Name == "reason")?.Value?.ToString();
            var guildId = command.GuildId ?? 0;

            if (string.IsNullOrEmpty(action))
            {
                await command.RespondAsync("❌ Action is required.", ephemeral: true);
                return;
            }

            switch (action.ToLower())
            {
                case "add":
                    if (string.IsNullOrEmpty(domain))
                    {
                        await command.RespondAsync("❌ Domain is required for adding to whitelist.", ephemeral: true);
                        return;
                    }

                    var cleanDomain = ExtractDomainFromUrl(domain);
                    var guild = _client?.GetGuild(command.GuildId ?? 0);

                    using (var context = new NoPhishingDbContext())
                    {
                        // Check if already whitelisted
                        var existing = await context.WhitelistDomains
                            .FirstOrDefaultAsync(w => w.Domain == cleanDomain && w.GuildId == guildId && w.IsActive);

                        if (existing != null)
                        {
                            await command.RespondAsync($"❌ Domain `{cleanDomain}` is already whitelisted for this server.", ephemeral: true);
                            return;
                        }

                        var whitelist = new WhitelistDomain
                        {
                            Domain = cleanDomain,
                            GuildId = guildId,
                            GuildName = guild?.Name,
                            AddedByUserId = command.User.Id,
                            AddedByUsername = command.User.Username,
                            Reason = reason,
                            DateAdded = DateTime.UtcNow,
                            IsActive = true
                        };

                        context.WhitelistDomains.Add(whitelist);
                        await context.SaveChangesAsync();
                    }

                    var addEmbed = new EmbedBuilder()
                        .WithColor(Color.Green)
                        .WithTitle("✅ Domain Added to Whitelist")
                        .WithDescription($"Domain `{cleanDomain}` has been added to the server whitelist.")
                        .AddField("Domain", cleanDomain, true)
                        .AddField("Added By", command.User.Username, true)
                        .AddField("Reason", reason ?? "Not specified", false)
                        .WithFooter("NoPhishing Bot - Whitelist Management")
                        .WithTimestamp(DateTimeOffset.Now)
                        .Build();

                    await command.RespondAsync(embed: addEmbed);
                    Console.WriteLine($"Domain {cleanDomain} added to whitelist by {command.User.Username} in guild {guildId}");
                    break;

                case "remove":
                    if (string.IsNullOrEmpty(domain))
                    {
                        await command.RespondAsync("❌ Domain is required for removing from whitelist.", ephemeral: true);
                        return;
                    }

                    var removeDomain = ExtractDomainFromUrl(domain);

                    using (var context = new NoPhishingDbContext())
                    {
                        var existing = await context.WhitelistDomains
                            .FirstOrDefaultAsync(w => w.Domain == removeDomain && w.GuildId == guildId && w.IsActive);

                        if (existing == null)
                        {
                            await command.RespondAsync($"❌ Domain `{removeDomain}` is not in the whitelist for this server.", ephemeral: true);
                            return;
                        }

                        existing.IsActive = false;
                        await context.SaveChangesAsync();
                    }

                    var removeEmbed = new EmbedBuilder()
                        .WithColor(Color.Orange)
                        .WithTitle("🗑️ Domain Removed from Whitelist")
                        .WithDescription($"Domain `{removeDomain}` has been removed from the server whitelist.")
                        .AddField("Domain", removeDomain, true)
                        .AddField("Removed By", command.User.Username, true)
                        .WithFooter("NoPhishing Bot - Whitelist Management")
                        .WithTimestamp(DateTimeOffset.Now)
                        .Build();

                    await command.RespondAsync(embed: removeEmbed);
                    Console.WriteLine($"Domain {removeDomain} removed from whitelist by {command.User.Username} in guild {guildId}");
                    break;

                case "list":
                    using (var context = new NoPhishingDbContext())
                    {
                        var whitelistDomains = await context.WhitelistDomains
                            .Where(w => w.GuildId == guildId && w.IsActive)
                            .OrderBy(w => w.Domain)
                            .Take(25)
                            .ToListAsync();

                        var listEmbed = new EmbedBuilder()
                            .WithColor(Color.Blue)
                            .WithTitle("📋 Server Whitelist")
                            .WithDescription(whitelistDomains.Count == 0 
                                ? "No domains are currently whitelisted for this server."
                                : $"Showing {whitelistDomains.Count} whitelisted domains:");

                        if (whitelistDomains.Count > 0)
                        {
                            var domainList = string.Join("\n", whitelistDomains.Select(w => 
                                $"🔹 `{w.Domain}` - Added by {w.AddedByUsername} on {w.DateAdded:yyyy-MM-dd}"));
                            listEmbed.AddField("Whitelisted Domains", domainList.Length > 1024 
                                ? domainList.Substring(0, 1021) + "..." 
                                : domainList, false);
                        }

                        listEmbed.WithFooter("NoPhishing Bot - Whitelist Management")
                            .WithTimestamp(DateTimeOffset.Now);

                        await command.RespondAsync(embed: listEmbed.Build(), ephemeral: true);
                    }
                    break;

                default:
                    await command.RespondAsync("❌ Invalid action. Use `add`, `remove`, or `list`.", ephemeral: true);
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error handling whitelist command: {ex.Message}");
            await command.RespondAsync("❌ An error occurred while processing the whitelist command.", ephemeral: true);
        }
    }

    private static async Task HandleBlacklistCommand(SocketSlashCommand command)
    {
        try
        {
            var action = command.Data.Options?.FirstOrDefault(x => x.Name == "action")?.Value?.ToString();
            var domain = command.Data.Options?.FirstOrDefault(x => x.Name == "domain")?.Value?.ToString();
            var reason = command.Data.Options?.FirstOrDefault(x => x.Name == "reason")?.Value?.ToString();

            if (string.IsNullOrEmpty(action))
            {
                await command.RespondAsync("❌ Action is required.", ephemeral: true);
                return;
            }

            switch (action.ToLower())
            {
                case "add":
                    if (string.IsNullOrEmpty(domain))
                    {
                        await command.RespondAsync("❌ Domain is required for adding to blacklist.", ephemeral: true);
                        return;
                    }

                    var cleanDomain = ExtractDomainFromUrl(domain);

                    using (var context = new NoPhishingDbContext())
                    {
                        // Check if already blacklisted
                        var existing = await context.ScamDomains
                            .FirstOrDefaultAsync(s => s.Domain == cleanDomain && s.IsActive);

                        if (existing != null)
                        {
                            await command.RespondAsync($"❌ Domain `{cleanDomain}` is already blacklisted.", ephemeral: true);
                            return;
                        }

                        var scamDomain = new ScamDomain
                        {
                            Domain = cleanDomain,
                            DetectionSource = "Manual",
                            DateAdded = DateTime.UtcNow,
                            IsActive = true,
                            Notes = reason ?? $"Manually added by {command.User.Username}"
                        };

                        context.ScamDomains.Add(scamDomain);
                        await context.SaveChangesAsync();

                        // Update in-memory cache
                        _scamDomainsCache[cleanDomain] = true;
                    }

                    var addEmbed = new EmbedBuilder()
                        .WithColor(Color.Red)
                        .WithTitle("🚫 Domain Added to Blacklist")
                        .WithDescription($"Domain `{cleanDomain}` has been added to the scam database.")
                        .AddField("Domain", cleanDomain, true)
                        .AddField("Added By", command.User.Username, true)
                        .AddField("Source", "Manual Addition", true)
                        .AddField("Reason", reason ?? "Not specified", false)
                        .WithFooter("NoPhishing Bot - Blacklist Management")
                        .WithTimestamp(DateTimeOffset.Now)
                        .Build();

                    await command.RespondAsync(embed: addEmbed);
                    Console.WriteLine($"Domain {cleanDomain} manually added to blacklist by {command.User.Username}");
                    break;

                case "remove":
                    if (string.IsNullOrEmpty(domain))
                    {
                        await command.RespondAsync("❌ Domain is required for removing from blacklist.", ephemeral: true);
                        return;
                    }

                    var removeDomain = ExtractDomainFromUrl(domain);

                    using (var context = new NoPhishingDbContext())
                    {
                        var existing = await context.ScamDomains
                            .FirstOrDefaultAsync(s => s.Domain == removeDomain && s.IsActive);

                        if (existing == null)
                        {
                            await command.RespondAsync($"❌ Domain `{removeDomain}` is not in the blacklist.", ephemeral: true);
                            return;
                        }

                        existing.IsActive = false;
                        await context.SaveChangesAsync();

                        // Update in-memory cache
                        _scamDomainsCache.TryRemove(removeDomain, out _);
                    }

                    var removeEmbed = new EmbedBuilder()
                        .WithColor(Color.Orange)
                        .WithTitle("✅ Domain Removed from Blacklist")
                        .WithDescription($"Domain `{removeDomain}` has been removed from the scam database.")
                        .AddField("Domain", removeDomain, true)
                        .AddField("Removed By", command.User.Username, true)
                        .WithFooter("NoPhishing Bot - Blacklist Management")
                        .WithTimestamp(DateTimeOffset.Now)
                        .Build();

                    await command.RespondAsync(embed: removeEmbed);
                    Console.WriteLine($"Domain {removeDomain} manually removed from blacklist by {command.User.Username}");
                    break;

                case "list":
                    using (var context = new NoPhishingDbContext())
                    {
                        var blacklistDomains = await context.ScamDomains
                            .Where(s => s.IsActive && s.DetectionSource == "Manual")
                            .OrderBy(s => s.Domain)
                            .Take(25)
                            .ToListAsync();

                        var listEmbed = new EmbedBuilder()
                            .WithColor(Color.Red)
                            .WithTitle("🚫 Manually Blacklisted Domains")
                            .WithDescription(blacklistDomains.Count == 0 
                                ? "No domains have been manually added to the blacklist."
                                : $"Showing {blacklistDomains.Count} manually blacklisted domains:");

                        if (blacklistDomains.Count > 0)
                        {
                            var domainList = string.Join("\n", blacklistDomains.Select(s => 
                                $"🔹 `{s.Domain}` - Added on {s.DateAdded:yyyy-MM-dd}"));
                            listEmbed.AddField("Blacklisted Domains", domainList.Length > 1024 
                                ? domainList.Substring(0, 1021) + "..." 
                                : domainList, false);
                        }

                        listEmbed.WithFooter("NoPhishing Bot - Blacklist Management")
                            .WithTimestamp(DateTimeOffset.Now);

                        await command.RespondAsync(embed: listEmbed.Build(), ephemeral: true);
                    }
                    break;

                default:
                    await command.RespondAsync("❌ Invalid action. Use `add`, `remove`, or `list`.", ephemeral: true);
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error handling blacklist command: {ex.Message}");
            await command.RespondAsync("❌ An error occurred while processing the blacklist command.", ephemeral: true);
        }
    }

    private static async Task HandleStatsCommand(SocketSlashCommand command)
    {
        try
        {
            var guildId = command.GuildId ?? 0;

            using (var context = new NoPhishingDbContext())
            {
                var thirtyDaysAgo = DateTime.UtcNow.AddDays(-30);
                var sevenDaysAgo = DateTime.UtcNow.AddDays(-7);

                var totalDetections = await context.DetectionLogs.CountAsync(d => d.GuildId == guildId);
                var recentDetections = await context.DetectionLogs.CountAsync(d => d.GuildId == guildId && d.DetectionDate >= thirtyDaysAgo);
                var weeklyDetections = await context.DetectionLogs.CountAsync(d => d.GuildId == guildId && d.DetectionDate >= sevenDaysAgo);
                var totalReports = await context.DomainReports.CountAsync(r => r.GuildId == guildId);
                var recentReports = await context.DomainReports.CountAsync(r => r.GuildId == guildId && r.ReportDate >= thirtyDaysAgo);
                var whitelistCount = await context.WhitelistDomains.CountAsync(w => w.GuildId == guildId && w.IsActive);
                var totalScamDomains = await context.ScamDomains.CountAsync(s => s.IsActive);

                var topDomains = await context.DetectionLogs
                    .Where(d => d.GuildId == guildId && d.DetectionDate >= thirtyDaysAgo)
                    .GroupBy(d => d.Domain)
                    .Select(g => new { Domain = g.Key, Count = g.Count() })
                    .OrderByDescending(x => x.Count)
                    .Take(5)
                    .ToListAsync();

                var statsEmbed = new EmbedBuilder()
                    .WithColor(Color.Blue)
                    .WithTitle("📊 Server Protection Statistics")
                    .WithDescription($"Protection statistics for **{_client?.GetGuild(command.GuildId ?? 0)?.Name}**")
                    .AddField("🛡️ Total Detections", totalDetections.ToString(), true)
                    .AddField("📅 Last 30 Days", recentDetections.ToString(), true)
                    .AddField("📆 Last 7 Days", weeklyDetections.ToString(), true)
                    .AddField("📝 Total Reports", totalReports.ToString(), true)
                    .AddField("📋 Recent Reports", recentReports.ToString(), true)
                    .AddField("✅ Whitelisted Domains", whitelistCount.ToString(), true)
                    .AddField("🗄️ Total Scam Database", $"{totalScamDomains} domains", false);

                if (topDomains.Count > 0)
                {
                    var topDomainsText = string.Join("\n", topDomains.Select(d => $"🔹 `{d.Domain}` ({d.Count} detections)"));
                    statsEmbed.AddField("🎯 Most Detected (30 days)", topDomainsText, false);
                }

                var isActive = IsDefendingModeActive(guildId);
                statsEmbed.AddField("🛡️ Protection Status", isActive ? "🟢 Active" : "🔴 Inactive", true);

                statsEmbed.WithFooter("NoPhishing Bot - Server Statistics")
                    .WithTimestamp(DateTimeOffset.Now);

                await command.RespondAsync(embed: statsEmbed.Build(), ephemeral: true);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error handling stats command: {ex.Message}");
            await command.RespondAsync("❌ An error occurred while retrieving statistics.", ephemeral: true);
        }
    }

    private static async Task HandleConfigCommand(SocketSlashCommand command)
    {
        try
        {
            var setting = command.Data.Options?.FirstOrDefault(x => x.Name == "setting")?.Value?.ToString();
            var value = command.Data.Options?.FirstOrDefault(x => x.Name == "value")?.Value?.ToString();
            var guildId = command.GuildId ?? 0;

            if (string.IsNullOrEmpty(setting))
            {
                await command.RespondAsync("❌ Setting is required.", ephemeral: true);
                return;
            }

            using (var context = new NoPhishingDbContext())
            {
                var config = await context.ServerConfigs.FirstOrDefaultAsync(c => c.GuildId == guildId);
                
                if (config == null)
                {
                    config = new ServerConfig
                    {
                        GuildId = guildId,
                        GuildName = _client?.GetGuild(command.GuildId ?? 0)?.Name
                    };
                    context.ServerConfigs.Add(config);
                }

                switch (setting.ToLower())
                {
                    case "show":
                        var showEmbed = new EmbedBuilder()
                            .WithColor(Color.Blue)
                            .WithTitle("⚙️ Server Configuration")
                            .WithDescription($"Current configuration for **{_client?.GetGuild(command.GuildId ?? 0)?.Name}**")
                            .AddField("🗑️ Auto Delete Scam Messages", config.AutoDeleteScamMessages ? "✅ Enabled" : "❌ Disabled", true)
                            .AddField("⚠️ Send Warning Messages", config.SendWarningMessages ? "✅ Enabled" : "❌ Disabled", true)
                            .AddField("📝 Log Detections", config.LogDetections ? "✅ Enabled" : "❌ Disabled", true)
                            .AddField("📢 Log Channel", config.LogChannelId?.ToString() ?? "Not set", true)
                            .AddField("👁️ Require Manual Review", config.RequireManualReview ? "✅ Enabled" : "❌ Disabled", true)
                            .AddField("🎯 Scam Detection Threshold", config.ScamThreshold.ToString(), true)
                            .AddField("🕒 Last Updated", config.LastUpdated.ToString("yyyy-MM-dd HH:mm"), true)
                            .AddField("👤 Updated By", config.UpdatedByUsername ?? "System", true)
                            .WithFooter("NoPhishing Bot - Server Configuration")
                            .WithTimestamp(DateTimeOffset.Now)
                            .Build();

                        await command.RespondAsync(embed: showEmbed, ephemeral: true);
                        break;

                    case "auto_delete":
                        if (string.IsNullOrEmpty(value))
                        {
                            await command.RespondAsync("❌ Value is required. Use `true` or `false`.", ephemeral: true);
                            return;
                        }
                        config.AutoDeleteScamMessages = value.ToLower() == "true";
                        break;

                    case "send_warnings":
                        if (string.IsNullOrEmpty(value))
                        {
                            await command.RespondAsync("❌ Value is required. Use `true` or `false`.", ephemeral: true);
                            return;
                        }
                        config.SendWarningMessages = value.ToLower() == "true";
                        break;

                    case "log_detections":
                        if (string.IsNullOrEmpty(value))
                        {
                            await command.RespondAsync("❌ Value is required. Use `true` or `false`.", ephemeral: true);
                            return;
                        }
                        config.LogDetections = value.ToLower() == "true";
                        break;

                    case "log_channel":
                        if (string.IsNullOrEmpty(value))
                        {
                            config.LogChannelId = null;
                        }
                        else if (ulong.TryParse(value.Replace("<#", "").Replace(">", ""), out var channelId))
                        {
                            config.LogChannelId = channelId;
                        }
                        else
                        {
                            await command.RespondAsync("❌ Invalid channel ID. Use a channel mention or ID.", ephemeral: true);
                            return;
                        }
                        break;

                    case "manual_review":
                        if (string.IsNullOrEmpty(value))
                        {
                            await command.RespondAsync("❌ Value is required. Use `true` or `false`.", ephemeral: true);
                            return;
                        }
                        config.RequireManualReview = value.ToLower() == "true";
                        break;

                    case "scam_threshold":
                        if (string.IsNullOrEmpty(value) || !int.TryParse(value, out var threshold) || threshold < 1 || threshold > 3)
                        {
                            await command.RespondAsync("❌ Scam threshold must be a number between 1 and 3.", ephemeral: true);
                            return;
                        }
                        config.ScamThreshold = threshold;
                        break;

                    default:
                        await command.RespondAsync("❌ Invalid setting.", ephemeral: true);
                        return;
                }

                if (setting.ToLower() != "show")
                {
                    config.LastUpdated = DateTime.UtcNow;
                    config.UpdatedByUserId = command.User.Id;
                    config.UpdatedByUsername = command.User.Username;
                    await context.SaveChangesAsync();

                    var updateEmbed = new EmbedBuilder()
                        .WithColor(Color.Green)
                        .WithTitle("✅ Configuration Updated")
                        .WithDescription($"Setting `{setting}` has been updated successfully.")
                        .AddField("Setting", setting, true)
                        .AddField("New Value", value ?? "Cleared", true)
                        .AddField("Updated By", command.User.Username, true)
                        .WithFooter("NoPhishing Bot - Configuration Management")
                        .WithTimestamp(DateTimeOffset.Now)
                        .Build();

                    await command.RespondAsync(embed: updateEmbed);
                    Console.WriteLine($"Config setting {setting} updated to '{value}' by {command.User.Username} in guild {guildId}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error handling config command: {ex.Message}");
            await command.RespondAsync("❌ An error occurred while updating configuration.", ephemeral: true);
        }
    }

    private static async Task HandleHistoryCommand(SocketSlashCommand command)
    {
        try
        {
            var domain = command.Data.Options?.FirstOrDefault(x => x.Name == "domain")?.Value?.ToString();
            var daysValue = command.Data.Options?.FirstOrDefault(x => x.Name == "days")?.Value;
            var days = daysValue != null ? (int)Convert.ToInt64(daysValue) : 7;
            var guildId = command.GuildId ?? 0;

            if (days > 90)
            {
                await command.RespondAsync("❌ Maximum history period is 90 days.", ephemeral: true);
                return;
            }

            var cutoffDate = DateTime.UtcNow.AddDays(-days);

            using (var context = new NoPhishingDbContext())
            {
                IQueryable<DetectionLog> query = context.DetectionLogs
                    .Where(d => d.GuildId == guildId && d.DetectionDate >= cutoffDate);

                if (!string.IsNullOrEmpty(domain))
                {
                    var cleanDomain = ExtractDomainFromUrl(domain);
                    query = query.Where(d => d.Domain == cleanDomain);
                }

                var detections = await query
                    .OrderByDescending(d => d.DetectionDate)
                    .Take(25)
                    .ToListAsync();

                var historyEmbed = new EmbedBuilder()
                    .WithColor(Color.Blue)
                    .WithTitle("📈 Detection History")
                    .WithDescription(string.IsNullOrEmpty(domain) 
                        ? $"Detection history for the last {days} days"
                        : $"Detection history for `{domain}` in the last {days} days");

                if (detections.Count == 0)
                {
                    historyEmbed.AddField("No Detections Found", 
                        string.IsNullOrEmpty(domain) 
                            ? "No malicious domains were detected in this server during the specified period."
                            : "This domain has not been detected as malicious in the specified period.", false);
                }
                else
                {
                    var historyText = string.Join("\n", detections.Take(15).Select(d => 
                        $"🔹 `{d.Domain}` by {d.Username} in #{d.ChannelName} ({d.DetectionDate:MM-dd HH:mm})"));

                    if (historyText.Length > 1024)
                        historyText = historyText.Substring(0, 1021) + "...";

                    historyEmbed.AddField($"Recent Detections ({detections.Count})", historyText, false);

                    if (detections.Count > 15)
                    {
                        historyEmbed.AddField("Note", $"Showing 15 of {detections.Count} detections.", false);
                    }

                    // Add summary statistics
                    var uniqueDomains = detections.Select(d => d.Domain).Distinct().Count();
                    var uniqueUsers = detections.Select(d => d.Username).Distinct().Count();
                    
                    historyEmbed.AddField("Summary", 
                        $"**Unique Domains:** {uniqueDomains}\n" +
                        $"**Unique Users:** {uniqueUsers}\n" +
                        $"**Time Period:** {days} days", true);
                }

                historyEmbed.WithFooter("NoPhishing Bot - Detection History")
                    .WithTimestamp(DateTimeOffset.Now);

                await command.RespondAsync(embed: historyEmbed.Build(), ephemeral: true);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error handling history command: {ex.Message}");
            await command.RespondAsync("❌ An error occurred while retrieving detection history.", ephemeral: true);
        }
    }

    private static List<string> ExtractDomainsFromMessage(string content)
    {
        var domains = new List<string>();
        
        // URL regex pattern
        var urlPattern = @"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})";
        var matches = Regex.Matches(content, urlPattern, RegexOptions.IgnoreCase);
        
        foreach (Match match in matches)
        {
            if (match.Groups.Count > 1)
            {
                domains.Add(match.Groups[1].Value.ToLower());
            }
        }
        
        return domains.Distinct().ToList();
    }

    private static async Task LogDetectionToDatabase(SocketMessage message, List<(string url, string source)> scamUrls)
    {
        try
        {
            var guildChannel = message.Channel as SocketGuildChannel;
            if (guildChannel == null) return;

            using (var context = new NoPhishingDbContext())
            {
                foreach (var (url, source) in scamUrls)
                {
                    var domain = ExtractDomainFromUrl(url);
                    var detectionLog = new DetectionLog
                    {
                        Domain = domain,
                        GuildId = guildChannel.Guild.Id,
                        GuildName = guildChannel.Guild.Name,
                        UserId = message.Author.Id,
                        Username = message.Author.Username,
                        ChannelId = message.Channel.Id,
                        ChannelName = message.Channel.Name,
                        MessageId = message.Id,
                        MessageContent = message.Content.Length > 2000 ? message.Content.Substring(0, 2000) : message.Content,
                        DetectionSources = JsonConvert.SerializeObject(scamUrls.Where(s => ExtractDomainFromUrl(s.url) == domain).Select(s => s.source).ToList()),
                        DetectionDate = DateTime.UtcNow,
                        WasDeleted = true,
                        WasWarned = true,
                        ActionTaken = "Message deleted and warning sent"
                    };

                    context.DetectionLogs.Add(detectionLog);
                }

                await context.SaveChangesAsync();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error logging detection to database: {ex.Message}");
        }
    }

    private static async Task<bool> IsWhitelistedAsync(string domain, ulong guildId)
    {
        try
        {
            var normalizedDomain = ExtractDomainFromUrl(domain).ToLowerInvariant();
            
            using (var context = new NoPhishingDbContext())
            {
                return await context.WhitelistDomains
                    .AnyAsync(w => w.Domain == normalizedDomain && 
                                  (w.GuildId == guildId || w.GuildId == null) && 
                                  w.IsActive);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking whitelist: {ex.Message}");
            return false;
        }
    }
}
