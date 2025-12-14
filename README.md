# Transaction Debugger CLI

A powerful CLI tool to debug EVM transactions, decode traces into step by step call stack, and get AI-powered transaction summaries.

Very powerful for transactions that can hide internal reverts while the transaction might look like it succeeded (ex ERC4337 transactions).

**Important**: Works only with RPC nodes that support `debug_traceTransaction`, `debug_traceCall` and for the best results use an archive node.

## Features

- 🔍 **Transaction Debugging**: Find and analyze transaction reverts with detailed error messages
- 📊 **Trace Decoding**: Get full decoded transaction traces with function calls and parameters
- 🤖 **AI Summaries**: Get human-readable AI-powered transaction summaries using Gemini
- 🔮 **Transaction Simulation**: Test transaction execution before sending to the blockchain
- 🔗 **Explorer Links**: Clickable links to block explorers for easy navigation
- 🌐 **Multi-Chain Support**: Works with 50+ EVM-compatible networks

## Installation

### Global Installation (Recommended)

```bash
npm install -g tx-debugger-cli
# or
pnpm add -g tx-debugger-cli
# or
yarn add -g tx-debugger-cli
```

## Quick Start

After installation, you can start using the CLI immediately:

```bash
tx-debugger-cli --help
```

## Commands

### 1. Look for Reverts
Find and analyze transaction reverts with detailed error messages:

```bash
tx-debugger-cli look_for_revert -t 0x123... -r https://rpc-url.com -c 1 -e YOUR_ETHERSCAN_KEY
```

**Example:**
```bash
tx-debugger-cli look_for_revert \
  -t 0xabc123... \
  -r https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  -c 1 \
  -e YOUR_ETHERSCAN_KEY
```

### 2. Decode Transaction Trace
Get full decoded trace with function calls and parameters:

```bash
tx-debugger-cli decode_trace -t 0x123... -r https://rpc-url.com -c 1 -e YOUR_ETHERSCAN_KEY
```

**With JSON output (saves to `{txHash}.json`):**
```bash
tx-debugger-cli decode_trace -t 0x123... -r https://rpc-url.com -c 1 -e YOUR_ETHERSCAN_KEY -j
```

**With Mermaid diagram (saves to `{txHash}_diagram.md`):**
```bash
tx-debugger-cli decode_trace -t 0x123... -r https://rpc-url.com -c 1 -e YOUR_ETHERSCAN_KEY -d
```

**With both JSON and diagram:**
```bash
tx-debugger-cli decode_trace -t 0x123... -r https://rpc-url.com -c 1 -e YOUR_ETHERSCAN_KEY -j -d
```

### 3. AI Transaction Summary
Get AI-generated human readable summary of what happened in a transaction:

```bash
tx-debugger-cli summarize_transaction -t 0x123... -r https://rpc-url.com -c 1 -g YOUR_GEMINI_KEY -e YOUR_ETHERSCAN_KEY
```

### 4. Simulate Transaction
Test transaction execution before sending to the blockchain:

```bash
tx-debugger-cli simulate_transaction \
  --to 0x123... \
  --data 0x456... \
  --value 0x0 \
  --from 0x789... \
  -r https://rpc-url.com \
  -c 1 \
  -e YOUR_ETHERSCAN_KEY
```

## Command Options

| Option | Description | Required | Example |
|--------|-------------|----------|---------|
| `-t, --txHash` | Transaction hash (0x...) | Yes* | `0xabc123...` |
| `-r, --rpcUrl` | RPC URL for the chain | Yes | `https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY` |
| `-c, --chainId` | Chain ID | Yes | `1` (Ethereum), `137` (Polygon) |
| `-e, --etherscanApiKey` | Etherscan API key for contract names | No | `YOUR_ETHERSCAN_KEY` |
| `-g, --geminiApiKey` | Gemini API key for AI summaries | Yes** | `YOUR_GEMINI_KEY` |
| `--no-links` | Disable clickable explorer links | No | - |
| `-j, --json` | Save output as JSON file (`{txHash}.json`) | No | - |
| `-d, --diagram` | Generate Mermaid sequence diagram (`{txHash}_diagram.md`) | No | - |
| `-b, --blockNumber` | Block number for simulation | No | `latest`, `0x123` |

*Required for all commands except `simulate_transaction`  
**Required only for `summarize_transaction` command

## Supported Networks

The tool supports 50+ EVM-compatible networks including:

- **Ethereum**: Mainnet, Sepolia, Goerli
- **Polygon**: Mainnet, Amoy Testnet
- **BSC**: Mainnet, Testnet
- **Arbitrum**: One, Nova
- **Optimism**: Mainnet, Sepolia
- **Avalanche**: Mainnet, Fuji Testnet
- **Fantom**: Mainnet
- **Base**: Mainnet, Sepolia
- **Scroll**: Mainnet
- **Linea**: Mainnet
- **zkSync**: Mainnet
- **Blast**: Mainnet, Sepolia
- **Cronos**: Mainnet
- **Moonbeam/Moonriver**: Mainnet

## API Keys

### Etherscan API Key
Get your free API key from [Etherscan.io](https://etherscan.io/apis):
- Used for contract name resolution
- Works across all supported networks
- Optional but recommended for better readability

### Gemini API Key
Get your API key from [Google AI Studio](https://makersuite.google.com/app/apikey):
- Required for AI-powered transaction summaries
- Uses Gemini 2.5 Flash Lite model
- Free tier available

## Examples

### Debug a Failed Transaction
```bash
tx-debugger-cli look_for_revert \
  -t 0x1234567890abcdef... \
  -r https://polygon-rpc.com \
  -c 137 \
  -e YOUR_ETHERSCAN_KEY
```

### Get Full Transaction Trace
```bash
tx-debugger-cli decode_trace \
  -t 0x1234567890abcdef... \
  -r https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  -c 1 \
  -e YOUR_ETHERSCAN_KEY
```

### Get Trace with JSON and Diagram
```bash
tx-debugger-cli decode_trace \
  -t 0x1234567890abcdef... \
  -r https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  -c 1 \
  -e YOUR_ETHERSCAN_KEY \
  -j \
  -d
```
This will create:
- `{txHash}.json` - Full trace data in JSON format
- `{txHash}_diagram.md` - Mermaid sequence diagram (visualize at [mermaid.live](https://mermaid.live))

### Get AI Summary
```bash
tx-debugger-cli summarize_transaction \
  -t 0x1234567890abcdef... \
  -r https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  -c 1 \
  -g YOUR_GEMINI_KEY \
  -e YOUR_ETHERSCAN_KEY
```

### Simulate a Transaction
```bash
tx-debugger-cli simulate_transaction \
  --to 0xA0b86a33E6441c8C06DDD4b6c4C4c4c4c4c4c4c4c \
  --data 0xa9059cbb000000000000000000000000... \
  --value 0x0 \
  --from 0x1234567890123456789012345678901234567890 \
  -r https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  -c 1 \
  -e YOUR_ETHERSCAN_KEY
```

## Screenshot

![Transaction Debugger CLI in action](cli_decode_transaction.png)


# tx-debugger-cli_cli
