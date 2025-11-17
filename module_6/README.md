# Module 6: ERC20 Token Implementation with Hardhat

This module demonstrates how to create, deploy, and test an ERC20 token using Hardhat and OpenZeppelin Contracts.

## Prerequisites

- Node.js v22.14.0 or higher
- npm (comes with Node.js)
- Basic understanding of Solidity and JavaScript

## Project Overview

This project implements a custom ERC20 token called "MyToken" (MTK) with the following features:
- Standard ERC20 functionality (transfer, balance, approve, etc.)
- Owner-restricted minting capability
- Initial supply minted to deployer on deployment

---

## Step 1: Set Up Development Environment ✅

### 1.1 Install Node.js and npm
- Node.js and npm should be installed on your system
- Verify installation:
  ```bash
  node --version
  npm --version
  ```

### 1.2 Set Up Hardhat Project ✅
The Hardhat project has been initialized with:
- ✅ `hardhat.config.js` - Hardhat configuration file
- ✅ `contracts/` - Directory for Solidity contracts
- ✅ `test/` - Directory for test files
- ✅ `ignition/modules/` - Directory for Hardhat Ignition deployment modules

**Dependencies installed:**
- ✅ `hardhat` - Development environment
- ✅ `@nomicfoundation/hardhat-toolbox` - Hardhat plugins and tools
- ✅ `@openzeppelin/contracts` - Secure smart contract library

**Installation commands (already executed):**
```bash
npm init -y
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
npm install @openzeppelin/contracts
```

---

## Step 2: Write the ERC20 Token Contract ✅

### 2.1 Contract Location ✅
- ✅ Contract file created: `contracts/MyToken.sol`

### 2.2 Contract Implementation ✅
The contract implements:
- ✅ ERC20 standard using OpenZeppelin's `ERC20.sol`
- ✅ Access control using OpenZeppelin's `Ownable.sol`
- ✅ Constructor that mints initial supply to deployer
- ✅ Owner-restricted `mint()` function

**Contract Details:**
- **Name**: MyToken
- **Symbol**: MTK
- **Solidity Version**: ^0.8.28
- **Initial Supply**: Configurable via constructor parameter

**Current Implementation:**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyToken is ERC20, Ownable {
    constructor(uint256 initialSupply) ERC20("MyToken", "MTK") Ownable(msg.sender) {
        _mint(msg.sender, initialSupply);
    }

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}
```

---

## Step 3: Write a Deployment Script ✅

### 3.1 Hardhat Ignition Module ✅
- ✅ Deployment module created: `ignition/modules/MyToken.js`

**Implementation using Hardhat Ignition:**
```javascript
const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");
const { parseEther } = require("ethers");

const DEFAULT_INITIAL_SUPPLY = parseEther("1000000");

module.exports = buildModule("MyTokenModule", (m) => {
    const initialSupply = m.getParameter("initialSupply", DEFAULT_INITIAL_SUPPLY);
    const myToken = m.contract("MyToken", [initialSupply]);
    return { myToken };
});
```

**Benefits of Ignition:**
- Automatic state tracking
- Smart re-deployment detection
- Parameter support via command line
- Better dependency management

### 3.2 Alternative: Traditional Deployment Script ⚠️ TODO
**Note:** The task description also mentions a traditional `scripts/deploy.js` file. While Ignition is the modern approach, you can optionally create a traditional script for comparison.

**TODO:** Create `scripts/deploy.js` with traditional deployment approach:
```javascript
const { ethers } = require("hardhat");

async function main() {
    const [deployer] = await ethers.getSigners();
    console.log("Deploying contract with account:", deployer.address);
    
    const balance = await ethers.provider.getBalance(deployer.address);
    console.log("Account balance:", ethers.formatEther(balance), "ETH");

    const MyToken = await ethers.getContractFactory("MyToken");
    const initialSupply = ethers.parseEther("1000000");
    const myToken = await MyToken.deploy(initialSupply);
    
    await myToken.waitForDeployment();
    const address = await myToken.getAddress();
    console.log("MyToken deployed to:", address);
    
    const deployerBalance = await myToken.balanceOf(deployer.address);
    console.log("Deployer token balance:", ethers.formatEther(deployerBalance), "MTK");
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exitCode = 1;
    });
```

---

## Step 4: Compile and Deploy ✅

### 4.1 Compile the Contract ✅
Compile your contracts:
```bash
npx hardhat compile
```

**Expected Output:**
- Contracts compiled successfully
- Artifacts generated in `artifacts/` directory
- Build info stored in `artifacts/build-info/`

### 4.2 Deploy to Local Hardhat Network ✅

**Option A: Using Hardhat Ignition (Recommended) ✅**

1. Start a local Hardhat node (in a separate terminal):
   ```bash
   npx hardhat node
   ```

2. Deploy using Ignition:
   ```bash
   npx hardhat ignition deploy ignition/modules/MyToken.js --network localhost
   ```

**Expected Output:**
```
Hardhat Ignition 🚀

Deploying [ MyTokenModule ]

Batch #1
  Executed MyTokenModule#MyToken

[ MyTokenModule ] successfully deployed 🚀

Deployed Addresses

MyTokenModule#MyToken - 0x...
```

**Option B: Using Traditional Script (if created) ⚠️ TODO**
```bash
npx hardhat run scripts/deploy.js --network localhost
```

### 4.3 Deploy with Custom Parameters
You can override the default initial supply when deploying:
```bash
npx hardhat ignition deploy ignition/modules/MyToken.js --network localhost \
  --parameters '{"MyTokenModule":{"initialSupply":"2000000000000000000000000"}}'
```

**Note:** Parameter values must be in wei (with 18 decimals). The example above deploys with 2,000,000 tokens.

---

## Step 5: Test Your Token ⚠️ TODO

### 5.1 Test Framework Setup ✅
- ✅ Hardhat test framework configured (Mocha + Chai)
- ✅ `@nomicfoundation/hardhat-toolbox` includes testing utilities

### 5.2 Create Test File ⚠️ TODO
**TODO:** Create `test/MyToken.js` with comprehensive test cases.

**Required Test Cases:**

1. **Deployment Tests:**
   - ✅ Should deploy with correct initial supply
   - ✅ Should set the correct token name and symbol
   - ✅ Should set the deployer as owner

2. **Minting Tests:**
   - ✅ Should allow owner to mint tokens
   - ✅ Should prevent non-owner from minting

3. **Transfer Tests:**
   - ✅ Should transfer tokens between accounts
   - ✅ Should fail if insufficient balance
   - ✅ Should update balances after transfer

4. **Edge Cases:**
   - ✅ Should handle zero transfers
   - ✅ Should prevent transfer to zero address

**Example Test Structure:**
```javascript
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("MyToken", function () {
    let myToken;
    let owner;
    let addr1;
    let addr2;
    const initialSupply = ethers.parseEther("1000000");

    beforeEach(async function () {
        [owner, addr1, addr2] = await ethers.getSigners();
        const MyToken = await ethers.getContractFactory("MyToken");
        myToken = await MyToken.deploy(initialSupply);
        await myToken.waitForDeployment();
    });

    describe("Deployment", function () {
        it("Should deploy with correct initial supply", async function () {
            const ownerBalance = await myToken.balanceOf(owner.address);
            expect(ownerBalance).to.equal(initialSupply);
        });

        it("Should set the correct token name and symbol", async function () {
            expect(await myToken.name()).to.equal("MyToken");
            expect(await myToken.symbol()).to.equal("MTK");
        });

        it("Should set the deployer as owner", async function () {
            expect(await myToken.owner()).to.equal(owner.address);
        });
    });

    describe("Minting", function () {
        it("Should allow owner to mint tokens", async function () {
            const mintAmount = ethers.parseEther("1000");
            await myToken.mint(addr1.address, mintAmount);
            
            const balance = await myToken.balanceOf(addr1.address);
            expect(balance).to.equal(mintAmount);
        });

        it("Should prevent non-owner from minting", async function () {
            const mintAmount = ethers.parseEther("1000");
            
            await expect(
                myToken.connect(addr1).mint(addr1.address, mintAmount)
            ).to.be.revertedWithCustomError(myToken, "OwnableUnauthorizedAccount");
        });
    });

    describe("Transfers", function () {
        it("Should transfer tokens between accounts", async function () {
            const transferAmount = ethers.parseEther("100");
            
            await myToken.transfer(addr1.address, transferAmount);
            
            const addr1Balance = await myToken.balanceOf(addr1.address);
            expect(addr1Balance).to.equal(transferAmount);
            
            const ownerBalance = await myToken.balanceOf(owner.address);
            expect(ownerBalance).to.equal(initialSupply - transferAmount);
        });

        it("Should fail if insufficient balance", async function () {
            const transferAmount = ethers.parseEther("2000000"); // More than initial supply
            
            await expect(
                myToken.transfer(addr1.address, transferAmount)
            ).to.be.revertedWithCustomError(myToken, "ERC20InsufficientBalance");
        });

        it("Should update balances after transfer", async function () {
            const transferAmount = ethers.parseEther("500");
            
            await myToken.transfer(addr1.address, transferAmount);
            await myToken.transfer(addr1.address, transferAmount);
            
            const addr1Balance = await myToken.balanceOf(addr1.address);
            expect(addr1Balance).to.equal(transferAmount * 2n);
        });
    });

    describe("Edge Cases", function () {
        it("Should handle zero transfers", async function () {
            await expect(
                myToken.transfer(addr1.address, 0)
            ).to.not.be.reverted;
        });

        it("Should prevent transfer to zero address", async function () {
            const transferAmount = ethers.parseEther("100");
            
            await expect(
                myToken.transfer(ethers.ZeroAddress, transferAmount)
            ).to.be.revertedWithCustomError(myToken, "ERC20InvalidReceiver");
        });
    });
});
```

### 5.3 Run Tests ⚠️ TODO
Once tests are created, run them with:
```bash
npx hardhat test
```

To run with gas reporting:
```bash
REPORT_GAS=true npx hardhat test
```

---

## Step 6: Extend Functionality ✅

### 6.1 Owner-Restricted Minting ✅
- ✅ `mint()` function implemented
- ✅ Protected with `onlyOwner` modifier
- ✅ Allows owner to create new tokens

### 6.2 Token Transfers ✅
- ✅ Standard ERC20 `transfer()` function available
- ✅ Inherited from OpenZeppelin's ERC20 implementation
- ✅ Includes balance checks and event emissions

### 6.3 Edge Case Testing ⚠️ TODO
**TODO:** Implement comprehensive edge case tests:
- ✅ Transferring more tokens than available balance
- ✅ Transferring to zero address
- ✅ Zero amount transfers
- ✅ Minting to zero address
- ✅ Large amount transfers
- ✅ Multiple consecutive transfers

---

## Deliverables Checklist

### Required Files:
- ✅ `contracts/MyToken.sol` - The ERC20 token contract
- ✅ `ignition/modules/MyToken.js` - Hardhat Ignition deployment module
- ⚠️ `scripts/deploy.js` - Traditional deployment script (optional, for comparison)
- ⚠️ `test/MyToken.js` - Comprehensive test suite

### Test Coverage:
- ⚠️ Deployment tests (initial supply, name, symbol, owner)
- ⚠️ Minting tests (owner can mint, non-owner cannot)
- ⚠️ Transfer tests (normal transfers, balance updates)
- ⚠️ Edge case tests (insufficient balance, zero address, etc.)

---

## Usage Commands

### Compile Contracts
```bash
npx hardhat compile
```

### Run Tests
```bash
npx hardhat test
```

### Run Tests with Gas Reporting
```bash
REPORT_GAS=true npx hardhat test
```

### Start Local Hardhat Network
```bash
npx hardhat node
```

### Deploy Using Ignition
```bash
npx hardhat ignition deploy ignition/modules/MyToken.js --network localhost
```

### Deploy Using Traditional Script (if created)
```bash
npx hardhat run scripts/deploy.js --network localhost
```

### Check Deployment Status
```bash
npx hardhat ignition status --network localhost
```

### List All Deployments
```bash
npx hardhat ignition list --network localhost
```

---

## Project Structure

```
module_6/
├── contracts/
│   ├── MyToken.sol          ✅ ERC20 token contract
│   └── Lock.sol              (example contract)
├── test/
│   ├── MyToken.js            ⚠️ TODO: Create test file
│   └── Lock.js               (example test)
├── scripts/
│   └── deploy.js             ⚠️ TODO: Optional traditional script
├── ignition/
│   └── modules/
│       ├── MyToken.js        ✅ Ignition deployment module
│       └── Lock.js           (example module)
├── hardhat.config.js         ✅ Hardhat configuration
├── package.json              ✅ Project dependencies
└── README.md                 ✅ This file
```

---

## Key Concepts Learned

### ERC20 Standard
- Fungible token standard on Ethereum
- Functions: `transfer()`, `balanceOf()`, `approve()`, `transferFrom()`
- Events: `Transfer`, `Approval`

### OpenZeppelin Contracts
- Audited, secure smart contract library
- Provides `ERC20` base implementation
- Provides `Ownable` for access control

### Hardhat Ignition
- Modern deployment system for Hardhat
- Automatic state tracking
- Parameter support
- Smart re-deployment detection

### Testing with Hardhat
- Mocha test framework
- Chai assertion library
- Hardhat network helpers
- Gas reporting capabilities

---

## Next Steps

1. ⚠️ **Create comprehensive test suite** (`test/MyToken.js`)
2. ⚠️ **Run all tests** and ensure 100% pass rate
3. ⚠️ **Optional:** Create traditional deployment script for comparison
4. ✅ **Deploy to testnet** (optional, requires testnet configuration)
5. ✅ **Verify contract** on block explorer (if deployed to testnet)

---

## Troubleshooting

### Common Issues

**Issue:** `Error: Cannot find module '@openzeppelin/contracts'`
- **Solution:** Run `npm install @openzeppelin/contracts`

**Issue:** `Error: Contract "MyToken" not found`
- **Solution:** Run `npx hardhat compile` first

**Issue:** `Error: Insufficient funds`
- **Solution:** Ensure your account has enough ETH for gas fees

**Issue:** Tests failing with custom errors
- **Solution:** Use `revertedWithCustomError()` instead of `revertedWith()` for OpenZeppelin v5

---

## Resources

- [Hardhat Documentation](https://hardhat.org/docs)
- [OpenZeppelin Contracts](https://docs.openzeppelin.com/contracts)
- [ERC20 Token Standard](https://eips.ethereum.org/EIPS/eip-20)
- [Hardhat Ignition Guide](https://hardhat.org/ignition/docs)

---

## License

MIT
