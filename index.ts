#!/usr/bin/env node

import { Command } from 'commander';
import { ethers, formatEther, Provider } from 'ethers';
import chalk from 'chalk';
import { GoogleGenAI } from '@google/genai';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { UNISWAP_V3_ERROR_CODES } from './constants';

const CONTRACT_INFO_CACHE = new Map<string, { name: string }>();

const ETHERSCAN_V2_API = 'https://api.etherscan.io/v2/api';

const CHAIN_TO_EXPLORER: Record<number, string> = {
    1: 'etherscan.io',                  // Ethereum Mainnet
    11155111: 'sepolia.etherscan.io',    // Sepolia Testnet
    137: 'polygonscan.com',             // Polygon
    80002: 'amoy.polygonscan.com',      // Polygon Amoy Testnet
    56: 'bscscan.com',                 // BNB Smart Chain
    97: 'testnet.bscscan.com',         // BNB Smart Chain Testnet
    42161: 'arbiscan.io',               // Arbitrum One
    42170: 'nova.arbiscan.io',          // Arbitrum Nova
    10: 'optimistic.etherscan.io',       // OP Mainnet
    11155420: 'sepolia-optimism.etherscan.io', // OP Sepolia
    43114: 'snowtrace.io',              // Avalanche
    43113: 'testnet.snowtrace.io',      // Avalanche Fuji Testnet
    250: 'ftmscan.com',                 // Fantom
    8453: 'basescan.org',                // Base
    84532: 'sepolia.basescan.org',      // Base Sepolia
    534352: 'scrollscan.com',           // Scroll
    59144: 'lineascan.build',           // Linea
    324: 'explorer.zksync.io',          // zkSync
    81457: 'blastscan.io',              // Blast
    168587773: 'sepolia.blastscan.io',  // Blast Sepolia
    25: 'cronoscan.com',               // Cronos
    1284: 'moonscan.io',               // Moonbeam
    1285: 'moonriver.moonscan.io',     // Moonriver
};

// Hyperlink utility functions
const createHyperlink = (text: string, url: string): string => {
    const OSC = '\u001b]';
    const BEL = '\u0007';
    const SEP = ';';
    return [OSC, '8', SEP, SEP, url, BEL, text, OSC, '8', SEP, SEP, BEL].join('');
};

const getExplorerUrl = (address: string, chainId: number, type: 'address' | 'tx' = 'address'): string | null => {
    const domain = CHAIN_TO_EXPLORER[chainId];
    if (!domain) return null;
    const path = type === 'tx' ? 'tx' : 'address';
    return `https://${domain}/${path}/${address}`;
};

const formatAddressWithLink = (address: string, chainId: number, enableLinks: boolean = true): string => {
    const coloredAddress = chalk.cyan(address);

    if (!enableLinks) {
        return coloredAddress;
    }

    const url = getExplorerUrl(address, chainId);
    if (!url) {
        return coloredAddress; 
    }

    return createHyperlink(coloredAddress, url);
};

const formatTxHashWithLink = (txHash: string, chainId: number, enableLinks: boolean = true): string => {
    const coloredTxHash = chalk.cyan(txHash);

    if (!enableLinks) {
        return coloredTxHash;
    }

    const url = getExplorerUrl(txHash, chainId, 'tx');
    if (!url) {
        return coloredTxHash;
    }

    return createHyperlink(coloredTxHash, url);
};

type RawTraceCall = {
    from: string; gas: string; gasUsed: string; to: string; input: string;
    output?: string; error?: string; value: string; type: string; calls?: RawTraceCall[];
};
type DecodedSignature = {
    functionName: string; functionSignature: string;
    parameters: Array<{ name: string; type: string; value: string }>;
};
type SimplifiedTraceCall = {
    type: string; from: string; fromContractName: string; to: string; toContractName: string;
    functionSelector: string; decodedFunctionSelector?: DecodedSignature; value: string;
    valueInEther: string; gasUsed: string; reverted: boolean; revertReason?: string;
    calls: SimplifiedTraceCall[];
};

type DecodedTraceCall = {
    type: string;
    from: string;
    fromContractName: string;
    to: string;
    toContractName: string;
    functionSelector: string;
    decodedFunctionSelector: DecodedSignature;
    value: string;
    valueInEther: string;
    gasUsed: string;
    reverted: boolean;
    revertReason?: string;
    calls: DecodedTraceCall[];
};

const getContractName = async (address: string, provider: Provider, chainId: number, etherscanApiKey?: string): Promise<string> => {
    if (CONTRACT_INFO_CACHE.has(address)) return CONTRACT_INFO_CACHE.get(address)!.name;
    try {
        const code = await provider.getCode(address);
        if (code === '0x') {
            // Try to resolve ENS name for EOA
            try {
                const ensName = await provider.lookupAddress(address);
                if (ensName) {
                    CONTRACT_INFO_CACHE.set(address, { name: `EOA (${ensName})` });
                    return `EOA (${ensName})`;
                }
            } catch (e) {
                // ENS resolution failed, continue with default EOA
            }
            CONTRACT_INFO_CACHE.set(address, { name: 'EOA' });
            return 'Account';
        }

        // Try to get contract name from the contract itself
        let name = undefined;
        try {
            const contract = new ethers.Contract(address, ['function name() view returns (string)'], provider);
            name = await Promise.race([contract.name(), new Promise((_, reject) => setTimeout(() => reject(), 2000))]);
            if (typeof name === 'string' && name.length > 0) {
                CONTRACT_INFO_CACHE.set(address, { name });
                return name;
            }
        } catch (e) {
            // Contract doesn't have name() function or call failed
        }

        // Fallback to Etherscan if name not found in contract
        if (name === undefined && etherscanApiKey) {
            console.log(chalk.blue(`   🔍 Looking up contract ${address} on chain ${chainId} via Etherscan API...`));
            try {
                const etherscanInfo = await fetchContractInfoFromEtherscan(address, chainId, etherscanApiKey);
                if (etherscanInfo) {
                    CONTRACT_INFO_CACHE.set(address, { name: etherscanInfo.name });
                    return etherscanInfo.name;
                }
            } catch (e) {
                console.log(chalk.red(`   ❌ Etherscan lookup failed: ${e}`));
            }
        }

    } catch (e) { }

    const fallbackName = 'Unknown Contract';
    CONTRACT_INFO_CACHE.set(address, { name: fallbackName });
    return fallbackName;
};

const fetchFunctionSignature = async (selector: string): Promise<string | null> => {
    try {
        const response = await fetch(`https://www.4byte.directory/api/v1/signatures/?hex_signature=${selector}`);
        if (!response.ok) return null;
        const data = (await response.json()) as { results?: { id: number; text_signature: string }[] };
        if (data.results && data.results.length > 0) {
            return data.results.sort((a, b) => a.id - b.id)[0].text_signature;
        }
    } catch (error) {
        console.warn(chalk.yellow(`Warning: Could not fetch signature for ${selector}.`));
    }
    return null;
};

const fetchContractInfoFromEtherscan = async (
    address: string,
    chainId: number,
    apiKey: string
): Promise<{ name: string; isVerified: boolean } | null> => {
    try {
        const params = new URLSearchParams({
            chainid: chainId.toString(),
            module: 'contract',
            action: 'getsourcecode',
            address: address,
        });

        if (apiKey) {
            params.append('apikey', apiKey);
        }

        const url = `${ETHERSCAN_V2_API}?${params.toString()}`;

        const response = await fetch(url);
        if (!response.ok) {
            return null;
        }

        const data = await response.json() as {
            status: string;
            message?: string;
            result: Array<{
                ContractName: string;
                SourceCode: string;
                ABI: string;
            }>;
        };

        if (data.status === '0' && data.message === 'NOTOK' && (data.result as any)?.includes('Invalid chainid')) {
            return null;
        }

        if (data.status === '1' && data.result && data.result.length > 0) {
            const contract = data.result[0];
            const isVerified = !!(contract.SourceCode && contract.SourceCode !== '');
            const name = contract.ContractName || 'Unknown Contract';

            console.log(chalk.blue(`📋 Fetched Etherscan info for ${name}, Verified: ${isVerified}`));

            return {
                name: isVerified ? name : `Unverified Contract (${name})`,
                isVerified
            };
        }
    } catch (error) {
        console.log(chalk.yellow(`   ⚠️  Etherscan API lookup failed: ${error}`));
    }

    return null;
};

const decodeFunctionCall = async (input: string): Promise<DecodedSignature | null> => {
    if (!input || input === '0x' || input.length < 10) return null;
    const selector = input.slice(0, 10);
    const signature = await fetchFunctionSignature(selector);
    if (!signature) return null;
    try {
        const expectedMinLength = 10;
        if (input.length < expectedMinLength) {
            return null;
        }
        if (signature.includes('isValidSignature(bytes32,bytes)')) {
            const minLengthForIsValidSignature = 10 + 32 + 32 + 32;
            if (input.length < minLengthForIsValidSignature) {
                return null;
            }
        }
        const iface = new ethers.Interface([`function ${signature}`]);
        const decoded = iface.parseTransaction({ data: input });
        if (decoded) {
            return {
                functionName: decoded.name,
                functionSignature: signature,
                parameters: decoded.args.map((arg, i) => ({
                    name: decoded.fragment.inputs[i]?.name || `param${i}`,
                    type: decoded.fragment.inputs[i]?.type,
                    value: arg.toString(),
                })),
            };
        }
    } catch (e) {
        console.warn(chalk.yellow(`Warning: Failed to decode function call: ${e}`));
    }
    return null;
};

const decodeAndFetchSignatures = async (
    input: string
): Promise<{ decodings: DecodedSignature[]; signatures: string[] }> => {
    if (!input || input === '0x' || input.length < 10)
        return { decodings: [], signatures: [] };

    const selector = input.slice(0, 10);
    const signature = await fetchFunctionSignature(selector);
    if (!signature) return { decodings: [], signatures: [] };

    const decodings: DecodedSignature[] = [];
    try {
        const expectedMinLength = 10;
        if (input.length < expectedMinLength) {
            console.warn(chalk.yellow(`Warning: Input data too short for function call: ${input}`));
            return { decodings: [], signatures: [signature] };
        }
        if (signature.includes('isValidSignature(bytes32,bytes)')) {
            const minLengthForIsValidSignature = 10 + 32 + 32 + 32;
            if (input.length < minLengthForIsValidSignature) {
                console.warn(chalk.yellow(`Warning: Input data too short for isValidSignature call: ${input}`));
                return { decodings: [], signatures: [signature] };
            }
        }
        const iface = new ethers.Interface([`function ${signature}`]);
        const decoded = iface.parseTransaction({ data: input });
        if (decoded) {
            decodings.push({
                functionName: decoded.name,
                functionSignature: signature,
                parameters: decoded.args.map((arg, i) => ({
                    name: decoded.fragment.inputs[i]?.name || `param${i}`,
                    type: decoded.fragment.inputs[i]?.type,
                    value: arg.toString()
                }))
            });
        }
    } catch (e) {
        console.warn(chalk.yellow(`Warning: Failed to decode function call with signature ${signature}: ${e}`));
        return { decodings: [], signatures: [signature] };
    }
    return { decodings, signatures: [signature] };
};

const getRevertReason = (output?: string): string => {
    if (!output || !output.startsWith('0x08c379a0')) return 'Execution reverted without a reason string';
    try {
        return new ethers.Interface(['function Error(string)']).decodeErrorResult('Error', output)[0];
    } catch (e) {
        return 'Execution reverted with unrecognized error format.';
    }
};

const decodeUniswapError = (errorMessage: string): string | null => {
    // Check if the error message is a known Uniswap V3 error code
    const trimmedError = errorMessage.trim().replace(/^["']|["']$/g, '');
    const errorInfo = UNISWAP_V3_ERROR_CODES[trimmedError];
    
    if (errorInfo) {
        return `${errorInfo.description} (${errorInfo.source})`;
    }
    
    return null;
};

const formatRevertReason = (reason: string): string => {
    const uniswapExplanation = decodeUniswapError(reason);
    
    if (uniswapExplanation) {
        return `${reason} - ${chalk.yellow(uniswapExplanation)}`;
    }
    
    return reason;
};

const transformTrace = async (call: RawTraceCall, provider: Provider, chainId: number, etherscanApiKey?: string): Promise<SimplifiedTraceCall> => {
    const [fromContractName, toContractName, decodedFunctionSelector] = await Promise.all([
        getContractName(call.from, provider, chainId, etherscanApiKey),
        getContractName(call.to, provider, chainId, etherscanApiKey),
        decodeFunctionCall(call.input)
    ]);
    const reverted = !!call.error;
    return {
        type: call.type,
        from: call.from, fromContractName,
        to: call.to, toContractName,
        functionSelector: call.input.slice(0, 10),
        decodedFunctionSelector: decodedFunctionSelector ?? undefined,
        value: call.value ? BigInt(call.value).toString() : '0',
        valueInEther: call.value ? formatEther(BigInt(call.value)) : '0',
        gasUsed: call.gasUsed ? BigInt(call.gasUsed).toString() : '0',
        reverted,
        revertReason: reverted ? (call.error === 'execution reverted' ? getRevertReason(call.output) : call.error) : undefined,
        calls: call.calls ? await Promise.all(call.calls.map(c => transformTrace(c, provider, chainId, etherscanApiKey))) : [],
    };
};

const transformDecodedTrace = async (
    call: RawTraceCall,
    provider: Provider,
    chainId: number,
    etherscanApiKey?: string
): Promise<DecodedTraceCall> => {
    const { decodings, signatures } = await decodeAndFetchSignatures(call.input);
    const reverted = !!call.error;

    const [fromContractName, toContractName] = await Promise.all([
        getContractName(call.from, provider, chainId, etherscanApiKey),
        getContractName(call.to, provider, chainId, etherscanApiKey)
    ]);

    return {
        type: call.type,
        from: call.from,
        fromContractName,
        to: call.to,
        toContractName,
        functionSelector: call.input.slice(0, 10),
        decodedFunctionSelector: decodings[0] || {
            functionName: 'Unknown',
            functionSignature: 'Unknown',
            parameters: []
        },
        value: call.value ? BigInt(call.value).toString() : '0',
        valueInEther: call.value ? formatEther(BigInt(call.value)) : '0',
        gasUsed: call.gasUsed ? BigInt(call.gasUsed).toString() : '0',
        reverted,
        revertReason: reverted
            ? call.error === 'execution reverted'
                ? getRevertReason(call.output)
                : call.error
            : undefined,
        calls: call.calls
            ? await Promise.all(call.calls.map((c) => transformDecodedTrace(c, provider, chainId, etherscanApiKey)))
            : []
    };
};

const findRevertedCalls = (calls: SimplifiedTraceCall[]): SimplifiedTraceCall[] => {
    const reverted: SimplifiedTraceCall[] = [];
    const traverse = (callList: SimplifiedTraceCall[]) => {
        for (const call of callList) {
            if (call.reverted) reverted.push(call);
            if (call.calls?.length > 0) traverse(call.calls);
        }
    };
    traverse(calls);
    return reverted;
};

const findDeepestRevertedCall = (calls: SimplifiedTraceCall[]): SimplifiedTraceCall | null => {
    let deepestReverted: SimplifiedTraceCall | null = null;
    let maxDepth = -1;
    const traverse = (callList: SimplifiedTraceCall[], depth = 0) => {
        for (const call of callList) {
            if (call.reverted && depth > maxDepth) {
                deepestReverted = call;
                maxDepth = depth;
            }
            if (call.calls?.length > 0) traverse(call.calls, depth + 1);
        }
    };
    traverse(calls);
    return deepestReverted;
};

const generateTraceDiagram = (trace: DecodedTraceCall): string => {
    const sequence: Array<{ from: string; to: string; function: string; status: string; revertReason?: string }> = [];
    
    // Collect all calls in sequence order
    const collectCalls = (call: DecodedTraceCall) => {
        const functionName = call.decodedFunctionSelector?.functionName !== 'Unknown' 
            ? call.decodedFunctionSelector.functionName 
            : call.functionSelector !== '0x' 
                ? `0x${call.functionSelector.slice(2, 10)}` 
                : 'TRANSFER';
        
        sequence.push({
            from: call.fromContractName,
            to: call.toContractName,
            function: functionName,
            status: call.reverted ? '❌' : '✅',
            revertReason: call.reverted ? call.revertReason : undefined
        });
        
        // Process nested calls
        if (call.calls && call.calls.length > 0) {
            call.calls.forEach(nestedCall => collectCalls(nestedCall));
        }
    };
    
    collectCalls(trace);
    
    // Get all unique participants (contracts)
    const participants = new Set<string>();
    sequence.forEach(call => {
        participants.add(call.from);
        participants.add(call.to);
    });
    const participantList = Array.from(participants);
    
    // Build Mermaid sequence diagram
    const lines: string[] = [];
    lines.push('```mermaid');
    lines.push('sequenceDiagram');
    
    // Add participants
    participantList.forEach((participant, index) => {
        // Clean participant names for Mermaid (remove special chars, limit length)
        const cleanName = participant.replace(/[^a-zA-Z0-9_]/g, '_').substring(0, 30);
        lines.push(`    participant ${cleanName} as ${participant}`);
    });
    lines.push('');
    
    // Add sequence of calls
    sequence.forEach((call) => {
        const fromClean = call.from.replace(/[^a-zA-Z0-9_]/g, '_').substring(0, 30);
        const toClean = call.to.replace(/[^a-zA-Z0-9_]/g, '_').substring(0, 30);
        
        // Build the label with function name and status
        let label = `${call.function}`;
        if (call.revertReason) {
            // Truncate revert reason if too long
            const shortReason = call.revertReason.length > 50 
                ? call.revertReason.substring(0, 47) + '...' 
                : call.revertReason;
            label += ` (REVERT: ${shortReason})`;
        }
        
        // Use different arrow styles based on status
        if (call.status === '❌') {
            lines.push(`    ${fromClean} -x ${toClean}: ${label}`);
        } else {
            lines.push(`    ${fromClean} ->> ${toClean}: ${label}`);
        }
    });
    
    lines.push('```');
    
    return lines.join('\n');
};

const generateSummary = (txHash: string, deepestReverted: SimplifiedTraceCall | null): string => {
    if (!deepestReverted) return chalk.green(`✅ Transaction ${txHash} completed successfully.`);
    const signature = deepestReverted.decodedFunctionSelector?.functionSignature || `Unknown Function (${deepestReverted.functionSelector})`;
    const reason = deepestReverted.revertReason || 'Unknown reason';
    const formattedReason = formatRevertReason(reason);
    return chalk.red(`❌ Function ${chalk.cyan(signature)} reverted with reason: "${formattedReason}"`);
};

const displayDecodedTrace = (trace: DecodedTraceCall, depth = 0, chainId: number = 1, enableLinks: boolean = true): void => {
    const indent = '  '.repeat(depth);
    const statusIcon = trace.reverted ? chalk.red('❌') : chalk.green('✅');

    console.log(`${indent}${statusIcon} ${chalk.bold(trace.type)} Call`);
    console.log(`${indent}  From: ${chalk.yellow(trace.fromContractName)} (${formatAddressWithLink(trace.from, chainId, enableLinks)})`);
    console.log(`${indent}  To:   ${chalk.yellow(trace.toContractName)} (${formatAddressWithLink(trace.to, chainId, enableLinks)})`);

    if (trace.functionSelector !== '0x' && trace.decodedFunctionSelector.functionName !== 'Unknown') {
        console.log(`${indent}  Function: ${chalk.magenta(trace.decodedFunctionSelector.functionSignature)}`);
        if (trace.decodedFunctionSelector.parameters.length > 0) {
            console.log(`${indent}  Parameters:`);
            trace.decodedFunctionSelector.parameters.forEach(param => {
                console.log(`${indent}    - ${param.name} (${param.type}): ${chalk.gray(param.value)}`);
            });
        }
    }

    console.log(`${indent}  Value: ${chalk.blue(trace.valueInEther)} ETH`);
    console.log(`${indent}  Gas Used: ${chalk.blue(trace.gasUsed)}`);

    if (trace.reverted && trace.revertReason) {
        const formattedReason = formatRevertReason(trace.revertReason);
        console.log(`${indent}  ${chalk.bold.red('Revert Reason:')} ${chalk.red(formattedReason)}`);
    }

    if (trace.calls.length > 0) {
        console.log(`${indent}  ${chalk.bold('Nested Calls:')}`);
        trace.calls.forEach(call => displayDecodedTrace(call, depth + 1, chainId, enableLinks));
    }

    if (depth === 0) {
        console.log();
    }
};

const getAISummary = async (trace: DecodedTraceCall, geminiApiKey: string): Promise<string> => {
    const ai = new GoogleGenAI({
        apiKey: geminiApiKey
    });

    const tools = [{ googleSearch: {} }];
    const config = { thinkingConfig: { thinkingBudget: -1 }, tools };
    const model = 'gemini-2.5-flash-lite';
    const contents = [{
        role: 'user', parts: [{
            text: `Analyze this Ethereum transaction trace and provide a clear, step-by-step explanation. Use this exact format:

Here's what happened in this transaction:

- [First action with details]
- [Second action with details]  
- [Third action with details]
- [Continue with bullet points for each major step]

IMPORTANT FORMATTING RULES:
- Use simple bullet points with dashes (-)
- Do NOT use any markdown formatting like ** or * or # or []
- Write in plain text only
- Make each bullet point a complete, clear sentence
- Focus on what actually happened, not technical jargon
- Explain the purpose of each action in simple terms
- Include specific amounts and addresses when relevant
- Keep the explanation flowing and easy to read
- DO NOT format values, keep them as they are like ETH value and USDC and others, same for gas values

Focus on:
- Do not asume ETH and WETH is used always, chains might have different native and wrapped native currencies
- Key contract interactions and their purposes
- Token transfers with amounts and recipients
- Function calls and what they accomplish
- Important values and parameters
- Gas usage and refunds
- Final outcomes and results

Transaction Trace:
${JSON.stringify(trace, null, 2)}`
        }]
    }];

    try {
        const response = await ai.models.generateContent({ model, config, contents });
        return response.text || 'Unable to generate summary';
    } catch (error) {
        throw new Error(`Failed to generate AI summary: ${error}`);
    }
};

const validateInputs = (options: { txHash: string; rpcUrl: string; chainId: string; geminiApiKey?: string; etherscanApiKey?: string; noLinks?: boolean }): void => {
    const { txHash, rpcUrl, chainId, geminiApiKey, etherscanApiKey } = options;
    if (!txHash) { console.error(chalk.red('Error: Transaction hash is required. Use --txHash or -t')); process.exit(1); }
    if (!rpcUrl) { console.error(chalk.red('Error: RPC URL is required. Use --rpcUrl or -r')); process.exit(1); }
    if (!chainId) { console.error(chalk.red('Error: Chain ID is required. Use --chainId or -c')); process.exit(1); }
    if (!/^0x[a-fA-F0-9]{64}$/.test(txHash)) { console.error(chalk.red('Error: Invalid transaction hash format.')); process.exit(1); }
    try { new URL(rpcUrl); } catch (e) { console.error(chalk.red('Error: Invalid RPC URL format.')); process.exit(1); }
    const chainIdNum = parseInt(chainId, 10);
    if (isNaN(chainIdNum) || chainIdNum <= 0) { console.error(chalk.red('Error: Chain ID must be a positive integer.')); process.exit(1); }
    if (geminiApiKey !== undefined && !geminiApiKey) { console.error(chalk.red('Error: Gemini API key is required for AI summary. Use --geminiApiKey or -g')); process.exit(1); }
    if (etherscanApiKey !== undefined && !etherscanApiKey) { console.error(chalk.red('Error: Etherscan API key is required for contract name lookup. Use --etherscanApiKey or -e')); process.exit(1); }
};

const validateSimulationInputs = (options: { to: string; data: string; value: string; from: string; rpcUrl: string; chainId: string; blockNumber?: string; etherscanApiKey?: string }): { to: string; data: string; value: string; from: string; rpcUrl: string; chainId: string; blockNumber?: string; etherscanApiKey?: string } => {
    const { to, data, value, from, rpcUrl, chainId, blockNumber, etherscanApiKey } = options;
    if (!to) { console.error(chalk.red('Error: To address is required. Use --to')); process.exit(1); }
    if (!data) { console.error(chalk.red('Error: Transaction data is required. Use --data')); process.exit(1); }
    if (!from) { console.error(chalk.red('Error: From address is required. Use --from')); process.exit(1); }
    if (!rpcUrl) { console.error(chalk.red('Error: RPC URL is required. Use --rpcUrl or -r')); process.exit(1); }
    if (!chainId) { console.error(chalk.red('Error: Chain ID is required. Use --chainId or -c')); process.exit(1); }
    if (!/^0x[a-fA-F0-9]{40}$/.test(to)) { console.error(chalk.red('Error: Invalid to address format.')); process.exit(1); }
    if (!/^0x[a-fA-F0-9]{40}$/.test(from)) { console.error(chalk.red('Error: Invalid from address format.')); process.exit(1); }
    if (!/^0x[a-fA-F0-9]*$/.test(data)) { console.error(chalk.red('Error: Invalid data format. Must be hex string starting with 0x.')); process.exit(1); }
    
    // Normalize value: accept plain numbers and convert to hex
    let normalizedValue = value;
    if (!value.startsWith('0x')) {
        // Try to parse as a number and convert to hex
        const numValue = value === '' ? 0 : parseInt(value, 10);
        if (isNaN(numValue) || numValue < 0) {
            console.error(chalk.red('Error: Invalid value format. Must be a non-negative number or hex string starting with 0x.')); 
            process.exit(1);
        }
        normalizedValue = '0x' + numValue.toString(16);
    } else if (!/^0x[a-fA-F0-9]*$/.test(value)) {
        console.error(chalk.red('Error: Invalid value format. Must be hex string starting with 0x.')); 
        process.exit(1);
    }
    try { new URL(rpcUrl); } catch (e) { console.error(chalk.red('Error: Invalid RPC URL format.')); process.exit(1); }
    const chainIdNum = parseInt(chainId, 10);
    if (isNaN(chainIdNum) || chainIdNum <= 0) { console.error(chalk.red('Error: Chain ID must be a positive integer.')); process.exit(1); }
    if (blockNumber && !/^(0x[a-fA-F0-9]+|latest|earliest|pending)$/.test(blockNumber)) { console.error(chalk.red('Error: Invalid block number format. Use hex number, latest, earliest, or pending.')); process.exit(1); }
    if (etherscanApiKey !== undefined && !etherscanApiKey) { console.error(chalk.red('Error: Etherscan API key is required for contract name lookup. Use --etherscanApiKey or -e')); process.exit(1); }
    
    return { to, data, value: normalizedValue, from, rpcUrl, chainId, blockNumber, etherscanApiKey };
};

const debugTransaction = async (txHash: string, rpcUrl: string, chainId: string, enableLinks: boolean = true, etherscanApiKey?: string): Promise<void> => {
    const chainIdNumber = parseInt(chainId, 10);
    const formattedTxHash = enableLinks ? formatTxHashWithLink(txHash, chainIdNumber, enableLinks) : txHash;
    console.log(chalk.blue(`🔍 Debugging transaction ${chalk.bold(formattedTxHash)} on chain ${chalk.bold(chainId)}...`));
    console.log(chalk.blue(`   Using RPC: ${rpcUrl}`));

    try {
        const provider = new ethers.JsonRpcProvider(rpcUrl);
        const rawTrace = await provider.send('debug_traceTransaction', [txHash, { tracer: 'callTracer' }]);
        if (!rawTrace) {
            console.error(chalk.red('Failed to get trace. The transaction might not exist, be pending, or the RPC node does not support tracing.'));
            process.exit(1);
        }
        const simplifiedTrace = await transformTrace(rawTrace, provider, chainIdNumber, etherscanApiKey);
        const revertedCalls = findRevertedCalls([simplifiedTrace]);
        const deepestReverted = findDeepestRevertedCall([simplifiedTrace]);
        const summary = generateSummary(txHash, deepestReverted);
        console.log(`\n${chalk.bold('--- Summary ---')}`);
        console.log(summary);
        if (revertedCalls.length > 0) {
            console.log(`\n${chalk.bold('--- Reverted Call Details ---')}`);
            const deepest = findDeepestRevertedCall(revertedCalls);
            if (deepest) {
                console.log(`Showing details for the deepest reverted call:\n`);
                console.log(`  ${chalk.bold('From:')} ${chalk.yellow(deepest.fromContractName)} (${formatAddressWithLink(deepest.from, chainIdNumber, enableLinks)})`);
                console.log(`  ${chalk.bold('To:')}   ${chalk.yellow(deepest.toContractName)} (${formatAddressWithLink(deepest.to, chainIdNumber, enableLinks)})`);
                if (deepest.decodedFunctionSelector) {
                    console.log(`  ${chalk.bold('Function:')} ${chalk.cyan(deepest.decodedFunctionSelector.functionSignature)}`);
                    deepest.decodedFunctionSelector.parameters.forEach(p => {
                        console.log(`    - ${p.name} (${p.type}): ${chalk.magenta(p.value)}`);
                    });
                }
                const formattedReason = formatRevertReason(deepest.revertReason || 'Unknown reason');
                console.log(`  ${chalk.bold.red('Revert Reason:')} ${chalk.red(formattedReason)}`);
            }
        }
    } catch (error: any) {
        // Check for historical state error
        if (error?.error?.message?.includes('historical state is not available') || 
            error?.message?.includes('historical state is not available')) {
            console.error(chalk.red('\n❌ Error: Historical state is not available'));
            console.error(chalk.yellow('\nThis error occurs when:'));
            console.error(chalk.yellow('  • The RPC node is not an archive node (only keeps recent state)'));
            console.error(chalk.yellow('  • The transaction is too old for the RPC to trace'));
            console.error(chalk.yellow('  • The RPC provider doesn\'t support tracing for this block'));
            console.error(chalk.cyan('\n💡 Solutions:'));
            console.error(chalk.cyan('  1. Use an archive RPC node (e.g., Alchemy Archive, Infura Archive)'));
            console.error(chalk.cyan('  2. Try a different RPC provider that supports historical tracing'));
            console.error(chalk.cyan('  3. Check if the transaction is recent enough for your RPC provider'));
            process.exit(1);
        }
        console.error(chalk.red('\nAn unexpected error occurred:'), error);
        process.exit(1);
    }
};

const getDecodedTrace = async (txHash: string, rpcUrl: string, chainId: string, jsonOutput: boolean, enableLinks: boolean = true, etherscanApiKey?: string, saveDiagram: boolean = false): Promise<void> => {
    const chainIdNumber = parseInt(chainId, 10);
    const formattedTxHash = enableLinks ? formatTxHashWithLink(txHash, chainIdNumber, enableLinks) : txHash;
    console.log(chalk.blue(`🔍 Getting decoded trace for transaction ${chalk.bold(formattedTxHash)} on chain ${chalk.bold(chainId)}...`));
    console.log(chalk.blue(`   Using RPC: ${rpcUrl}`));

    try {
        const provider = new ethers.JsonRpcProvider(rpcUrl);
        const rawTrace = await provider.send('debug_traceTransaction', [txHash, { tracer: 'callTracer' }]);
        if (!rawTrace) {
            console.error(chalk.red('Failed to get trace. The transaction might not exist, be pending, or the RPC node does not support tracing.'));
            process.exit(1);
        }
        const decodedTrace = await transformDecodedTrace(rawTrace, provider, chainIdNumber, etherscanApiKey);
        
        if (jsonOutput) {
            const jsonContent = JSON.stringify({ 
                result: { 
                    trace: decodedTrace
                } 
            }, null, 2);
            const filename = `${txHash}.json`;
            writeFileSync(filename, jsonContent, 'utf-8');
            console.log(chalk.green(`\n✅ JSON trace saved to: ${chalk.bold(filename)}`));
        } else {
            console.log(`\n${chalk.bold('--- Decoded Transaction Trace ---')}`);
            displayDecodedTrace(decodedTrace, 0, chainIdNumber, enableLinks);
        }
        
        // Generate and save diagram to separate file if requested
        if (saveDiagram) {
            const diagram = generateTraceDiagram(decodedTrace);
            const diagramFilename = `${txHash}_diagram.md`;
            writeFileSync(diagramFilename, diagram, 'utf-8');
            console.log(chalk.green(`\n✅ Mermaid diagram saved to: ${chalk.bold(diagramFilename)}`));
            console.log(chalk.cyan(`💡 Tip: Open the file or paste it into https://mermaid.live to visualize it!`));
        }
    } catch (error: any) {
        // Check for historical state error
        if (error?.error?.message?.includes('historical state is not available') || 
            error?.message?.includes('historical state is not available')) {
            console.error(chalk.red('\n❌ Error: Historical state is not available'));
            console.error(chalk.yellow('\nThis error occurs when:'));
            console.error(chalk.yellow('  • The RPC node is not an archive node (only keeps recent state)'));
            console.error(chalk.yellow('  • The transaction is too old for the RPC to trace'));
            console.error(chalk.yellow('  • The RPC provider doesn\'t support tracing for this block'));
            console.error(chalk.cyan('\n💡 Solutions:'));
            console.error(chalk.cyan('  1. Use an archive RPC node (e.g., Alchemy Archive, Infura Archive)'));
            console.error(chalk.cyan('  2. Try a different RPC provider that supports historical tracing'));
            console.error(chalk.cyan('  3. Check if the transaction is recent enough for your RPC provider'));
            process.exit(1);
        }
        console.error(chalk.red('\nAn unexpected error occurred:'), error);
        process.exit(1);
    }
};

const getAITxSummary = async (txHash: string, rpcUrl: string, chainId: string, geminiApiKey: string, enableLinks: boolean = true, etherscanApiKey?: string): Promise<void> => {
    const chainIdNumber = parseInt(chainId, 10);
    const formattedTxHash = enableLinks ? formatTxHashWithLink(txHash, chainIdNumber, enableLinks) : txHash;
    console.log(chalk.blue(`🤖 Getting AI summary for transaction ${chalk.bold(formattedTxHash)} on chain ${chalk.bold(chainId)}...`));
    console.log(chalk.blue(`   Using RPC: ${rpcUrl}`));

    try {
        const provider = new ethers.JsonRpcProvider(rpcUrl);
        const rawTrace = await provider.send('debug_traceTransaction', [txHash, { tracer: 'callTracer' }]);
        if (!rawTrace) {
            console.error(chalk.red('Failed to get trace. The transaction might not exist, be pending, or the RPC node does not support tracing.'));
            process.exit(1);
        }
        const decodedTrace = await transformDecodedTrace(rawTrace, provider, chainIdNumber, etherscanApiKey);
        console.log(chalk.blue(`\n🤖 Generating transaction summary...`));
        const summary = await getAISummary(decodedTrace, geminiApiKey);
        console.log(`\n${chalk.bold('--- AI Transaction Summary ---')}`);
        console.log(chalk.white(summary));
    } catch (error: any) {
        // Check for historical state error
        if (error?.error?.message?.includes('historical state is not available') || 
            error?.message?.includes('historical state is not available')) {
            console.error(chalk.red('\n❌ Error: Historical state is not available'));
            console.error(chalk.yellow('\nThis error occurs when:'));
            console.error(chalk.yellow('  • The RPC node is not an archive node (only keeps recent state)'));
            console.error(chalk.yellow('  • The transaction is too old for the RPC to trace'));
            console.error(chalk.yellow('  • The RPC provider doesn\'t support tracing for this block'));
            console.error(chalk.cyan('\n💡 Solutions:'));
            console.error(chalk.cyan('  1. Use an archive RPC node (e.g., Alchemy Archive, Infura Archive)'));
            console.error(chalk.cyan('  2. Try a different RPC provider that supports historical tracing'));
            console.error(chalk.cyan('  3. Check if the transaction is recent enough for your RPC provider'));
            process.exit(1);
        }
        console.error(chalk.red('\nAn unexpected error occurred:'), error);
        process.exit(1);
    }
};

const simulateTransaction = async (to: string, data: string, value: string, from: string, rpcUrl: string, chainId: string, blockNumber?: string, enableLinks: boolean = true, etherscanApiKey?: string): Promise<void> => {
    const chainIdNumber = parseInt(chainId, 10);
    console.log(chalk.blue(`🔮 Simulating transaction execution...`));
    console.log(chalk.blue(`   From: ${formatAddressWithLink(from, chainIdNumber, enableLinks)}`));
    console.log(chalk.blue(`   To: ${formatAddressWithLink(to, chainIdNumber, enableLinks)}`));
    console.log(chalk.blue(`   Value: ${value} ETH`));
    console.log(chalk.blue(`   Data: ${data}`));
    console.log(chalk.blue(`   Chain: ${chainId}`));
    if (blockNumber) { console.log(chalk.blue(`   Block: ${blockNumber}`)); }

    try {
        const provider = new ethers.JsonRpcProvider(rpcUrl);
        const txObject = { from: from, to: to, data: data, value: value };
        const targetBlock = blockNumber || 'latest';
        console.log(chalk.blue(`\n📊 Step 1: Estimating gas usage...`));
        try {
            const gasEstimate = await provider.estimateGas(txObject);
            console.log(chalk.green(`   ✅ Estimated gas: ${gasEstimate.toString()}`));
        } catch (error) {
            console.log(chalk.red(`   ❌ Gas estimation failed: ${error}`));
        }
        console.log(chalk.blue(`\n📊 Step 2: Simulating transaction call...`));
        try {
            const result = await provider.call(txObject);
            console.log(chalk.green(`   ✅ Call successful`));
            console.log(chalk.blue(`   📄 Return data: ${result}`));
        } catch (error) {
            console.log(chalk.red(`   ❌ Call failed: ${error}`));
        }
        console.log(chalk.blue(`\n📊 Step 3: Tracing simulated execution...`));
        try {
            const traceResult = await provider.send('debug_traceCall', [txObject, targetBlock, { tracer: 'callTracer' }]);
            if (traceResult) {
                console.log(chalk.green(`   ✅ Trace successful`));
                const decodedTrace = await transformDecodedTrace(traceResult, provider, chainIdNumber, etherscanApiKey);
                console.log(`\n${chalk.bold('--- Simulated Transaction Trace ---')}`);
                displayDecodedTrace(decodedTrace, 0, chainIdNumber, enableLinks);
                const revertedCalls = findRevertedCalls([decodedTrace]);
                const deepestReverted = findDeepestRevertedCall([decodedTrace]);
                if (revertedCalls.length > 0) {
                    console.log(`\n${chalk.bold.red('⚠️  Simulation Warning: Transaction would revert!')}`);
                    const summary = generateSummary('SIMULATION', deepestReverted);
                    console.log(summary);
                } else {
                    console.log(`\n${chalk.bold.green('✅ Simulation Result: Transaction would succeed!')}`);
                }
            } else {
                console.log(chalk.yellow(`   ⚠️  No trace available (RPC may not support tracing)`));
            }
        } catch (error) {
            console.log(chalk.red(`   ❌ Trace failed: ${error}`));
            console.log(chalk.yellow(`   ℹ️  This might be because the RPC doesn't support debug_traceCall`));
        }
    } catch (error: any) {
        // Check for historical state error
        if (error?.error?.message?.includes('historical state is not available') || 
            error?.message?.includes('historical state is not available')) {
            console.error(chalk.red('\n❌ Error: Historical state is not available'));
            console.error(chalk.yellow('\nThis error occurs when:'));
            console.error(chalk.yellow('  • The RPC node is not an archive node (only keeps recent state)'));
            console.error(chalk.yellow('  • The block number is too old for the RPC to trace'));
            console.error(chalk.yellow('  • The RPC provider doesn\'t support tracing for this block'));
            console.error(chalk.cyan('\n💡 Solutions:'));
            console.error(chalk.cyan('  1. Use an archive RPC node (e.g., Alchemy Archive, Infura Archive)'));
            console.error(chalk.cyan('  2. Try a different RPC provider that supports historical tracing'));
            console.error(chalk.cyan('  3. Use a more recent block number (or "latest")'));
            process.exit(1);
        }
        console.error(chalk.red('\nAn unexpected error occurred during simulation:'), error);
        process.exit(1);
    }
};

async function main() {
    // Read version from package.json
    // When compiled, __dirname points to dist/, so we need to go up one level
    let version = '0.0.1';
    try {
        const packageJsonPath = typeof __dirname !== 'undefined' 
            ? join(__dirname, '..', 'package.json')
            : join(process.cwd(), 'package.json');
        const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
        version = packageJson.version || version;
    } catch (error) {
        // Fallback to default version if package.json can't be read
        console.warn(chalk.yellow('Warning: Could not read version from package.json, using default'));
    }

    const program = new Command();
    program
        .name('tx-debugger-cli')
        .description('A CLI tool to debug EVM transactions.')
        .version(version);

    program
        .command('look_for_revert')
        .description('Look for any internal revert in a transaction')
        .option('-t, --txHash <hash>', 'The transaction hash to debug (e.g., 0x...)')
        .option('-r, --rpcUrl <url>', 'The RPC URL for the corresponding chain (e.g., https://polygon-rpc.com)')
        .option('-c, --chainId <id>', 'Chain ID for the transaction (e.g., 1 for Ethereum, 137 for Polygon)')
        .option('-e, --etherscanApiKey <key>', 'Your Etherscan API key for contract name lookup')
        .option('--no-links', 'Disable clickable links in output')
        .action(async (options) => {
            validateInputs(options);
            await debugTransaction(options.txHash, options.rpcUrl, options.chainId, !options.noLinks, options.etherscanApiKey);
        });

    program
        .command('decode_trace')
        .description('Get full decoded trace of a transaction.')
        .option('-t, --txHash <hash>', 'The transaction hash to trace (e.g., 0x...)')
        .option('-r, --rpcUrl <url>', 'The RPC URL for the corresponding chain (e.g., https://polygon-rpc.com)')
        .option('-c, --chainId <id>', 'Chain ID for the transaction (e.g., 1 for Ethereum, 137 for Polygon)')
        .option('-e, --etherscanApiKey <key>', 'Your Etherscan API key for contract name lookup')
        .option('-j, --json', 'Output as JSON format')
        .option('-d, --diagram', 'Save Mermaid sequence diagram to a separate file (txHash_diagram.md)')
        .option('--no-links', 'Disable clickable links in output')
        .action(async (options) => {
            validateInputs(options);
            await getDecodedTrace(options.txHash, options.rpcUrl, options.chainId, options.json, !options.noLinks, options.etherscanApiKey, options.diagram);
        });

    program
        .command('summarize_transaction')
        .description('Get an AI-generated summary of what happened in a transaction. Uses gemini-2.5-flash-lite.')
        .option('-t, --txHash <hash>', 'The transaction hash to analyze (e.g., 0x...)')
        .option('-r, --rpcUrl <url>', 'The RPC URL for the corresponding chain (e.g., https://polygon-rpc.com)')
        .option('-c, --chainId <id>', 'Chain ID for the transaction (e.g., 1 for Ethereum, 137 for Polygon)')
        .option('-g, --geminiApiKey <key>', 'Your Gemini API key for AI analysis')
        .option('-e, --etherscanApiKey <key>', 'Your Etherscan API key for contract name lookup')
        .option('--no-links', 'Disable clickable links in output')
        .action(async (options) => {
            validateInputs({ ...options, geminiApiKey: options.geminiApiKey });
            await getAITxSummary(options.txHash, options.rpcUrl, options.chainId, options.geminiApiKey, !options.noLinks, options.etherscanApiKey);
        });

    program
        .command('simulate_transaction')
        .description('Simulate a transaction execution before it gets executed on-chain and decodes everything.')
        .option('--to <address>', 'The contract address to call (e.g., 0x...)')
        .option('--data <hex>', 'The transaction data (function selector + parameters)')
        .option('--value <hex>', 'The ETH value to send (e.g., 0x0 for 0 ETH)')
        .option('--from <address>', 'The sender address (e.g., 0x...)')
        .option('-r, --rpcUrl <url>', 'The RPC URL for the corresponding chain (e.g., https://polygon-rpc.com)')
        .option('-c, --chainId <id>', 'Chain ID for the transaction (e.g., 1 for Ethereum, 137 for Polygon)')
        .option('-e, --etherscanApiKey <key>', 'Your Etherscan API key for contract name lookup')
        .option('-b, --blockNumber <block>', 'Block number to simulate against (default: latest)')
        .option('--no-links', 'Disable clickable links in output')
        .action(async (options) => {
            const normalizedOptions = validateSimulationInputs(options);
            await simulateTransaction(normalizedOptions.to, normalizedOptions.data, normalizedOptions.value, normalizedOptions.from, normalizedOptions.rpcUrl, normalizedOptions.chainId, normalizedOptions.blockNumber, !options.noLinks, normalizedOptions.etherscanApiKey);
        });


    await program.parseAsync(process.argv);
}

main();