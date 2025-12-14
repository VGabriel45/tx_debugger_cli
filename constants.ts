// Uniswap V3 Error Code Mappings
export const UNISWAP_V3_ERROR_CODES: Record<string, { description: string; source: string }> = {
    // LiquidityMath.sol
    'LS': { description: 'Liquidity Sub', source: 'LiquidityMath.sol' },
    'LA': { description: 'Liquidity Add', source: 'LiquidityMath.sol' },
    // Oracle.sol
    'OLD': { description: 'The target must be chronologically after the oldest observation', source: 'Oracle.sol' },
    'I': { description: 'The pool has not been initialized', source: 'Oracle.sol' },
    // Position.sol
    'NP': { description: 'Burn cannot be called for a position with 0 liquidity', source: 'Position.sol' },
    // Tick.sol
    'LO': { description: 'LiquidityGrossAfter must be less than MaxLiquidity', source: 'Tick.sol' },
    // TickMath.sol
    'T': { description: 'The given tick must be less than, or equal to, the maximum tick', source: 'TickMath.sol' },
    'R': { description: 'Second inequality must be < because the price can never reach the price at the max tick', source: 'TickMath.sol' },
    // TransferHelper.sol
    'TF': { description: 'Transfer Failed: errors with TF if transfer fails', source: 'TransferHelper.sol' },
    // UniswapV3Pool.sol
    'LOK': { description: 'The reentrancy guard. A transaction cannot re-enter the pool mid-swap', source: 'UniswapV3Pool.sol' },
    'TLU': { description: 'The lower tick must be below the upper tick', source: 'UniswapV3Pool.sol' },
    'TLM': { description: 'The lower tick must be greater, or equal to, the minimum tick', source: 'UniswapV3Pool.sol' },
    'TUM': { description: 'The upper tick must be lesser than, or equal to, the maximum tick', source: 'UniswapV3Pool.sol' },
    'AI': { description: 'The pool is already initialized', source: 'UniswapV3Pool.sol' },
    'M0': { description: 'Mint 0: The balance of token0 in the given pool before minting must be less than, or equal to, the balance after minting', source: 'UniswapV3Pool.sol' },
    'M1': { description: 'Mint 1: The balance of token1 in the given pool before minting must be less than, or equal to, the balance after minting', source: 'UniswapV3Pool.sol' },
    'AS': { description: 'amountSpecified cannot be zero', source: 'UniswapV3Pool.sol' },
    'SPL': { description: 'Square root price limit', source: 'UniswapV3Pool.sol' },
    'IIA': { description: 'Insufficient input amount: an insufficient amount of input token was sent during the callback', source: 'UniswapV3Pool.sol' },
    'L': { description: 'Liquidity in the pool must be greater than zero for a flash to be executed', source: 'UniswapV3Pool.sol' },
    'F0': { description: 'The balance of token0 in the given pool before the flash transaction must be less than, or equal to, the balance of token0 after the flash plus the fee', source: 'UniswapV3Pool.sol' },
    'F1': { description: 'The balance of token1 in the given pool before the flash transaction must be less than, or equal to, the balance of token1 after the flash plus the fee', source: 'UniswapV3Pool.sol' },
};