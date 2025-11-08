# Sample Hardhat Project

This project demonstrates a basic Hardhat use case. It comes with a sample contract, a test for that contract, and a Hardhat Ignition module that deploys that contract.

## Prerequisites
- Node.js v22.14.0 or higher
- npm (comes with Node.js)
- Metamask wallet with Avalanche Fuji testnet configured
- Testnet AVAX for gas fees

## Installation Steps

### 1. Install Dependencies

```shell
npm install
```

### 2. Configure Environment Variables

Create a `.env` file in the `module_5` directory with your Metamask private key:

```env
# Avalanche Fuji Testnet
AVALANCHE_TESTNET_RPC_URL=https://api.avax-test.network/ext/bc/C/rpc
AVALANCHE_TESTNET_CHAIN_ID=43113
AVALANCHE_TESTNET_PRIVATE_KEY=your_private_key_here
```

**Important Security Notes:**
- Never commit your `.env` file to version control
- The `.env` file is already in `.gitignore`
- To get your private key from Metamask:
  1. Open Metamask
  2. Click on your account (top right)
  3. Go to "Account Details"
  4. Click "Export Private Key"
  5. Enter your password
  6. Copy the private key (it may or may not include the `0x` prefix - both work)

### 3. Verify Configuration

The Hardhat configuration is set up for Avalanche Fuji testnet:
- **Network Name**: `avalancheFuji`
- **RPC URL**: `https://api.avax-test.network/ext/bc/C/rpc`
- **Chain ID**: `43113`

### 4. Usage

### 5. Compile Contracts

```shell
npx hardhat compile
```

### 6. Run Tests

```shell
npx hardhat test
```

### 7. Deploy Contract

```shell
npx hardhat run scripts/deploy.js --network avalancheFuji
```

### 8. Verify Contract
To verify the contract on Snowtrace, you need to have a Snowtrace API key. You can get it by creating an account on Snowtrace and then creating an API key.

```env
SNOWTRACE_API_KEY=your_snowtrace_api_key_here
```

Then you can verify the contract by running the following command:

```shell
npx hardhat verify --network avalancheFuji <contract_address>
```

### Sample contract deployment output
```shell
Hardhat Ignition 🚀

Deploying [ LockModule ]

Batch #1
  Executed LockModule#Lock

[ LockModule ] successfully deployed 🚀

Deployed Addresses

LockModule#Lock - 0x91DBBF6f152cccF56E337382505cFf2C5D34fa5E
```

### Sample contract verification output
```shell
Successfully submitted source code for contract
contracts/Lock.sol:Lock at 0x91DBBF6f152cccF56E337382505cFf2C5D34fa5E
for verification on the block explorer. Waiting for verification result...
```
Successfully verified contract Lock on the block explorer.

https://testnet.snowtrace.io/address/0x91DBBF6f152cccF56E337382505cFf2C5D34fa5E#code

The contract 0x91DBBF6f152cccF56E337382505cFf2C5D34fa5E has already been verified on Sourcify.

https://repo.sourcify.dev/contracts/full_match/43113/0x91DBBF6f152cccF56E337382505cFf2C5D34fa5E/


### Sample contract details URL
Contract details URL: [https://subnets-test.avax.network/c-chain/address/0x91DBBF6f152cccF56E337382505cFf2C5D34fa5E](https://subnets-test.avax.network/c-chain/address/0x91DBBF6f152cccF56E337382505cFf2C5D34fa5E)

### Source code:
All the source code is in the `module_5` folder of a GitHub repository.
You can find the repository [here](https://github.com/eugene-chekan/crypto-n-blockchain-practice/tree/main/module_5).