// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://v2.hardhat.org/ignition

const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");
const { parseEther } = require("ethers");

// Default initial supply of 1000000 tokens
const DEFAULT_INITIAL_SUPPLY = parseEther("1000000");

module.exports = buildModule("MyTokenModule", (m) => {
    // Get the initial supply from the module parameters
    const initialSupply = m.getParameter("initialSupply", DEFAULT_INITIAL_SUPPLY);

    const myToken = m.contract("MyToken", [initialSupply]);

    return { myToken };
});
