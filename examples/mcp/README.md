# Use SiteVigil from your AI agent

SiteVigil speaks the **Model Context Protocol (MCP)**. MCP is one open
protocol shared by many agents, so there is exactly **one** SiteVigil
server — you do not need a different build per agent. The only thing
that changes between agents is *where* the config snippet lives.

Everywhere below, the server command is the same:

```
sitevigil --mcp
```

(Requires SiteVigil installed: `pip install sitevigil`, or from a clone
`pip install git+https://github.com/aqles/sitevigil`.)

## Claude Code

```bash
claude mcp add sitevigil -- sitevigil --mcp
```

or a project-level `.mcp.json`:

```json
{ "mcpServers": { "sitevigil": { "command": "sitevigil", "args": ["--mcp"] } } }
```

## Claude Desktop

`claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{ "mcpServers": { "sitevigil": { "command": "sitevigil", "args": ["--mcp"] } } }
```

## Cursor

`.cursor/mcp.json` in your project (or `~/.cursor/mcp.json` globally):

```json
{ "mcpServers": { "sitevigil": { "command": "sitevigil", "args": ["--mcp"] } } }
```

## Windsurf

`~/.codeium/windsurf/mcp_config.json`:

```json
{ "mcpServers": { "sitevigil": { "command": "sitevigil", "args": ["--mcp"] } } }
```

## VS Code (Copilot / MCP)

`.vscode/mcp.json` — note VS Code calls the top-level key `servers`:

```json
{ "servers": { "sitevigil": { "command": "sitevigil", "args": ["--mcp"] } } }
```

## Gemini CLI

`~/.gemini/settings.json`:

```json
{ "mcpServers": { "sitevigil": { "command": "sitevigil", "args": ["--mcp"] } } }
```

## Agents without MCP

No problem — anything that can run a shell command can use the CLI and
read the structured output:

```bash
sitevigil example.com --json
```

## One honest limitation

This server uses MCP's **stdio** transport: the agent starts SiteVigil
as a local process. That covers the desktop/CLI agents above. Hosted
agents that can only reach *remote* MCP servers over HTTP cannot use a
stdio server yet — a remote (streamable HTTP) transport is on the
roadmap, not in this version.
