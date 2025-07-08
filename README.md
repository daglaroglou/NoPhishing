# NoPhishing Discord Bot

A C# Discord bot that automatically scans messages for links and detects potential scam or phishing URLs by checking them against a SQLite database. Now includes **slash commands** to control defending mode, **secure configuration** for token management, and **automatic database updates** from GitHub!

## Features

- 🔍 **Automatic Link Scanning**: Monitors all messages for URLs
- ⚠️ **Scam Detection**: Checks URLs against a SQLite database of known scam domains
- 🚨 **Real-time Alerts**: Sends warning messages when scam links are detected
- 💾 **SQLite Database**: High-performance, reliable database storage using Entity Framework Core
- 🛡️ **Safe Operation**: Bot ignores its own messages and other bots
- 🏠 **Guild-Only Commands**: **NEW!** All commands restricted to Discord servers for security
- ⚡ **Slash Commands**: Control defending mode with `/activate`, `/deactivate`, `/status`, `/update`, `/check`, `/report`, `/whitelist`, `/stats`, `/export`, `/config`, `/scan`, `/history`, and `/recent`
- 📝 **Interactive Reporting**: **NEW!** Report malicious domains using Discord's modal forms for better user experience
- 🎛️ **Toggle Protection**: Enable or disable link scanning on demand
- 🌐 **Triple Protection**: Local database + Phish.Sinking.Yachts + Anti-Fish API detection
- 🧠 **Auto-Learning**: **NEW!** Automatically adds API-detected domains to SQLite database
- 💾 **Persistent Settings**: **NEW!** Guild defending mode settings survive bot restarts
- 📦 **Database Migration**: **NEW!** Automatically migrates from legacy text files to SQLite
- ✅ **Whitelist Management**: **NEW!** Add trusted domains to prevent false positives
- 📊 **Advanced Statistics**: **NEW!** Comprehensive protection statistics and analysis
- 🔍 **Manual Scanning**: **NEW!** Scan historical messages for threats
- 📈 **Activity Tracking**: **NEW!** View detection history and recent activity
- ⚙️ **Server Configuration**: **NEW!** Customize bot behavior per server
- 📋 **Data Export**: **NEW!** Export data for analysis and reporting

## Triple-Layer Protection

The bot uses a sophisticated **three-tier detection system** for comprehensive threat analysis:

### 1. **SQLite Database** (Primary - Tier 1)
- Downloads from [Discord-AntiScam GitHub repository](https://github.com/Discord-AntiScam/scam-links)
- Updates automatically on startup using Entity Framework Core
- Community-maintained list of known scam domains stored in SQLite
- ⚡ **Instant lookup** with in-memory caching for maximum performance
- 📊 **Import tracking** with detailed logs and statistics

### 2. **Phish.Sinking.Yachts API** (Secondary - Tier 2)
- Real-time phishing detection via [phish.sinking.yachts](https://phish.sinking.yachts/)
- Community-driven phishing domain database
- 🌊 **Community intelligence** for emerging threats

### 3. **Anti-Fish API** (Tertiary - Tier 3)
- Advanced threat analysis via [anti-fish.bitflow.dev](https://anti-fish.bitflow.dev/)
- AI-powered scam detection engine
- 🐟 **Real-time analysis** for unknown threats

### Detection Flow:
Domain Found → Check Local Database → Check Phish.Sinking.Yachts → Check Anti-Fish API → Report if Flagged → Auto-Add New Domains
### **Manual vs Automatic Checking:**
- **Manual `/check`**: Full three-tier analysis with detailed reporting + auto-learning
- **Automatic Scanning**: Optimized two-tier (Local + Anti-Fish) for performance + auto-learning
- **Emergency Scanning**: Adds Sinking Yachts if Anti-Fish is unavailable + auto-learning
- **Auto-Learning**: **NEW!** All API detections automatically added to local database

## 🧠 Auto-Learning SQLite Database

The bot now features **intelligent auto-learning** with SQLite database storage that continuously improves protection:

### **How Auto-Learning Works:**
1. **API Detection**: When APIs detect a scam domain not in SQLite database
2. **Automatic Addition**: Domain is immediately added to `nophishing.db` SQLite database
3. **Instant Protection**: New domain becomes available for future checks via in-memory cache
4. **Source Attribution**: Records which API detected the domain with timestamps
5. **Thread-Safe**: Multiple detections handled safely using Entity Framework Core

### **Auto-Learning Process:**
New Domain Detected by API → Check SQLite DB → If Not Found → Add to Database → Update In-Memory Cache → Log Import Details

### **Benefits:**
✅ **Continuous Improvement**: Database grows with each new threat discovered  
✅ **Zero Maintenance**: No manual intervention required for new domains  
✅ **Faster Future Detection**: API-detected domains become local for instant lookup  
✅ **Community Contribution**: Local discoveries benefit from external intelligence  
✅ **Persistent Learning**: Added domains survive bot restarts in SQLite  
✅ **Import Tracking**: Detailed logs of all database imports and updates  
✅ **High Performance**: Entity Framework Core with in-memory caching  

### **Example Auto-Learning Log:**
```
🆕 New scam domain detected by Anti-Fish API: malicious-new-site.com
📝 Added new scam domain to database: malicious-new-site.com (detected by Anti-Fish API)
🗂️ SQLite database now contains 1,268 domains
📊 Import completed: 1 new domains, 0 skipped
```

### **Database Migration:**
```
🔄 Migrating legacy scam_links.txt to database...
📊 Imported 1,267 domains from legacy file
✅ Legacy migration completed successfully
🗑️ Legacy file backed up as scam_links.txt.bak
```

## 💾 Persistent Guild Settings

The bot now features **persistent storage** of defending mode settings per Discord server (guild):

### **How Persistence Works:**
1. **Guild-Specific Settings**: Each Discord server has its own defending mode state
2. **Automatic Storage**: Settings are saved to `bot_settings.json` when changed
3. **Restart Survival**: Defending mode settings survive bot restarts
4. **Thread-Safe Storage**: Multiple guild operations handled safely

### **Settings Storage:**
```json
{
  "Guilds": {
    "123456789012345678": {
      "GuildId": 123456789012345678,
      "DefendingModeActive": true,
      "LastActivated": "2025-01-07T10:30:00.000Z",
      "ActivatedBy": "AdminUser"
    }
  },
  "LastUpdated": "2025-01-07T10:30:00.000Z"
}
```

### **Benefits:**
✅ **No Manual Reactivation**: Bot remembers which servers had protection enabled  
✅ **Per-Server Control**: Each Discord server maintains independent settings  
✅ **Audit Trail**: Track who activated/deactivated defending mode and when  
✅ **Automatic Backup**: Settings are saved immediately when changed  
✅ **Zero Configuration**: Settings file is created automatically  

### **Files Created:**
- `bot_settings.json` - Guild defending mode settings (auto-generated)
- `nophishing.db` - SQLite database with scam domains (auto-generated)
- `scam_links.txt` - Legacy file (migrated to database on first run)

## 📝 Interactive Domain Reporting

The bot features an **interactive modal form system** for reporting potentially malicious domains:

### **How Reporting Works:**
1. **Easy Access**: Use the `/report` slash command
2. **Modal Form**: Discord opens an interactive form with three fields:
   - **Domain to Report** (required): The suspicious domain or URL
   - **Reason for Reporting** (optional): Why you think it's malicious
   - **Additional Details** (optional): Extra context or information
3. **Smart Processing**: Bot automatically normalizes domains and validates input
4. **Developer Notification**: Reports are sent to the configured developer via DM
5. **Database Storage**: All reports are saved to the database for review

### **Reporting Features:**
✅ **User-Friendly Interface**: Professional modal form instead of command parameters  
✅ **Flexible Input**: Accept full URLs or just domain names  
✅ **Rich Context**: Collect detailed reasons and additional information  
✅ **Automatic Validation**: Ensure required fields are filled  
✅ **Smart Normalization**: Clean up URLs to extract domains properly  
✅ **Dual Storage**: Save to database and attempt developer notification  
✅ **Detailed Responses**: Professional embed responses with report IDs  

### **Example Report Flow:**
```
User: /report
Bot: [Opens modal form]
User: [Fills form with domain, reason, details]
Bot: ✅ Report Submitted Successfully
     Domain: suspicious-site.com
     Report ID: A1B2C3D4E5F6
     Status: 📧 Sent to developer
```

## Slash Commands

**⚠️ Important**: All commands must be used in Discord servers (guilds), not in direct messages. The bot will respond with an error if commands are attempted in DMs.

### Core Protection Commands
| Command | Description | Usage |
|---------|-------------|-------|
| `/activate` | Enable defending mode - bot will scan messages for scam links | `/activate` |
| `/deactivate` | Disable defending mode - bot stops scanning messages | `/deactivate` |
| `/status` | Check current defending mode status, database info, persistence, auto-learning, and SQLite statistics | `/status` |

### Database & Scanning Commands
| Command | Description | Usage |
|---------|-------------|-------|
| `/update` | Manually trigger an update of the scam links database | `/update` |
| `/check` | Check a specific domain against the scam database using three-tier validation | `/check domain:example.com` |
| `/scan` | Manually scan recent messages in a channel for scam links | `/scan channel:#general messages:50` |

### Whitelist Management Commands
| Command | Description | Usage |
|---------|-------------|-------|
| `/whitelist add` | Add a trusted domain to the server whitelist | `/whitelist action:add domain:example.com reason:"Company website"` |
| `/whitelist remove` | Remove a domain from the server whitelist | `/whitelist action:remove domain:example.com` |
| `/whitelist list` | Show all whitelisted domains for this server | `/whitelist action:list` |

### Reporting & Analysis Commands
| Command | Description | Usage |
|---------|-------------|-------|
| `/report` | Report a potentially malicious domain to the developers using an interactive form | `/report` |
| `/stats` | Show comprehensive protection statistics for this server | `/stats` |
| `/history` | View domain detection history (optionally filtered by domain) | `/history domain:example.com days:7` |
| `/recent` | View recent bot activity (detections, reports, or updates) | `/recent type:detections count:10` |

### Configuration & Export Commands
| Command | Description | Usage |
|---------|-------------|-------|
| `/config` | Manage bot configuration settings for this server | `/config setting:auto_delete value:true` |
| `/export` | Export data for analysis (domains, reports, or detections) | `/export type:detections days:30` |

### Configuration Settings
The `/config` command allows you to customize bot behavior:

| Setting | Description | Values |
|---------|-------------|--------|
| `auto_delete` | Automatically delete messages containing scam links | `true`/`false` |
| `send_warnings` | Send warning messages when scams are detected | `true`/`false` |
| `log_detections` | Log all detections to the database | `true`/`false` |
| `log_channel` | Channel to send detection logs to | Channel ID or mention |
| `manual_review` | Require manual review before taking action | `true`/`false` |
| `scam_threshold` | Number of sources needed to confirm a scam | `1`, `2`, or `3` |
| `show` | Display current configuration settings | (no value needed) |

### Data Export Types
The `/export` command supports different data types:

| Type | Description | Fields Included |
|------|-------------|-----------------|
| `domains` | Export scam domains database | Domain, Source, Date Added, Notes |
| `reports` | Export user-submitted reports | Domain, Reporter, Reason, Date, Status |
| `detections` | Export scam detections in this server | Domain, User, Channel, Sources, Date, Actions |

## Setup

### Prerequisites

- .NET 9.0 or higher
- Discord account and server (where you have permissions to add bots)
- Basic knowledge of running .NET applications

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/daglaroglou/NoPhishing.git
   cd NoPhishing
   ```

2. **Install Dependencies**:
   ```bash
   dotnet restore
   ```

3. **Configure the Bot**:
- Make use of Environment User Secret variables.
   
   **Configuration Options:**
   - `DiscordBotToken`: Your Discord bot token (required)
   - `DeveloperUserId`: Your Discord user ID for receiving domain reports (optional)
   
   **Security Note**: For production, use user secrets or environment variables instead of appsettings.json:
   ```bash
   dotnet user-secrets set "DiscordBotToken" "YOUR_BOT_TOKEN_HERE"
   dotnet user-secrets set "DeveloperUserId" "YOUR_DISCORD_USER_ID_HERE"
   ```

4. **Build the Bot**:
   ```bash
   dotnet build
   ```

5. **Run the Bot**:
   ```bash
   dotnet run
   ```

### Discord Bot Setup

1. **Create a Discord Application**:
   - Go to https://discord.com/developers/applications
   - Click "New Application" and give it a name
   - Go to the "Bot" section and create a bot
   - Copy the bot token for configuration

2. **Required Bot Permissions**:
   - Read Messages/View Channels
   - Send Messages
   - Use Slash Commands
   - Manage Messages (to delete scam messages)
   - Read Message History
   - Add Reactions
   - Embed Links

3. **Invite the Bot**:
   - Go to OAuth2 → URL Generator
   - Select "bot" and "applications.commands" scopes
   - Select the required permissions above
   - Use the generated URL to invite the bot to your server

### Updating

To update the bot to the latest version:

1. **Pull the Latest Changes**:
   ```bash
   git pull origin main
   ```

2. **Rebuild the Application**:
   ```bash
   dotnet build
   ```

3. **Restart the Bot**:
   ```bash
   dotnet run
   ```

### Database Management

The bot automatically manages its SQLite database:

- **First Run**: Creates `nophishing.db` and migrates any existing `scam_links.txt` file
- **Automatic Updates**: Downloads and imports new domains from GitHub on startup
- **Auto-Learning**: Adds API-detected domains automatically during operation
- **Performance**: Uses in-memory caching for fast domain lookups

### Configuration Files

- `appsettings.json` - Bot configuration (Discord token)
- `bot_settings.json` - Persistent guild settings (auto-generated)
- `nophishing.db` - SQLite database (auto-generated)
- `scam_links.txt` - Legacy file (migrated on first run)

## Usage

- Invite the bot to your server using the OAuth2 URL generated in the Discord Developer Portal
- Ensure the bot has the necessary permissions to read messages, send messages, and manage messages
- **Important**: All commands must be used in Discord servers (guilds) - commands in DMs will be rejected
- Use the slash commands to control the bot and check links
- Monitor the bot's activity for real-time scam link detection

## Troubleshooting

- If the bot fails to start, check the console output for error messages
- Common issues include invalid token, missing permissions, or network connectivity problems
- Ensure your configuration is correctly set up (user secrets, environment variables, or appsettings.json)
- For dependency issues, ensure .NET 9.0 or higher is installed
- **Commands not working**: Ensure you're using commands in a Discord server, not in DMs
- **"Guild Required" error**: The bot's commands only work in servers where it's been invited

## Contributing

Contributions are welcome! To contribute to the project:

1. Fork the repository
2. Create a new branch for your feature or bug fix
3. Make your changes and commit them
4. Push your branch to your forked repository
5. Create a pull request describing your changes

Please ensure your code follows the existing C# style and conventions used in the project.

## License

This project is open source. Please check the repository for license details.

## Support

If you need help with the bot:
- Check the troubleshooting section above
- Review the console output for error messages
- Ensure all configuration is properly set up
- Verify the bot has the required Discord permissions