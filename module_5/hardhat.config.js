require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config({ override: true });

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  defaultNetwork: "hardhat",
  solidity: "0.8.28",
  networks: {
    avalancheFuji: {
      url: process.env.AVALANCHE_TESTNET_RPC_URL,
      chainId: parseInt(process.env.AVALANCHE_TESTNET_CHAIN_ID || "43113"),
      accounts: process.env.AVALANCHE_TESTNET_PRIVATE_KEY ? [process.env.AVALANCHE_TESTNET_PRIVATE_KEY] : [],
    },
  },
  sourcify: {
    enabled: true,
  },
  etherscan: {
    apiKey: {
      avalancheFujiTestnet: process.env.SNOWTRACE_API_KEY || "",
    },
    customChains: [
      {
        network: "avalancheFujiTestnet",
        chainId: 43113,
        urls: {
          apiURL: "https://api-testnet.snowtrace.io/api",
          browserURL: "https://testnet.snowtrace.io"
        }
      }
    ]
  },
};