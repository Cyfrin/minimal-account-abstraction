> [!IMPORTANT]  
> This repo is for demo purposes only. 

# Account Abstraction

<br/>
<p align="center">
<img src="./img/ethereum/account-abstraction-again.png" width="500" alt="aa">
</p>
<br/>

- [Account Abstraction](#account-abstraction)
  - [What is Account Abstraction?](#what-is-account-abstraction)
  - [What's this repo show?](#whats-this-repo-show)
  - [What does this repo not show?](#what-does-this-repo-not-show)
- [Getting Started](#getting-started)
  - [Requirements](#requirements)
  - [Installation](#installation)
- [Quickstart](#quickstart)
  - [Vanilla Foundry](#vanilla-foundry)
    - [Deploy - Arbitrum](#deploy---arbitrum)
    - [User operation - Arbitrum](#user-operation---arbitrum)
  - [zkSync Foundry](#zksync-foundry)
    - [Deploy - zkSync local network](#deploy---zksync-local-network)
      - [Additional Requirements](#additional-requirements)
      - [Setup - local node](#setup---local-node)
      - [Deploy - local node](#deploy---local-node)
    - [Deploy - zkSync Sepolia or Mainnet](#deploy---zksync-sepolia-or-mainnet)
- [Example Deployments](#example-deployments)
  - [zkSync (Sepolia)](#zksync-sepolia)
  - [Ethereum (Arbitrum)](#ethereum-arbitrum)
- [Account Abstraction zkSync Contract Deployment Flow](#account-abstraction-zksync-contract-deployment-flow)
  - [First time](#first-time)
  - [Subsequent times](#subsequent-times)
- [FAQ](#faq)
  - [What if I don't add the contract hash to factory deps?](#what-if-i-dont-add-the-contract-hash-to-factory-deps)
  - [Why can't we do these deployments with foundry or cast?](#why-cant-we-do-these-deployments-with-foundry-or-cast)
  - [Why can I use `forge create --legacy` to deploy a regular contract?](#why-can-i-use-forge-create---legacy-to-deploy-a-regular-contract)
- [Acknowledgements](#acknowledgements)
- [Disclaimer](#disclaimer)

## What is Account Abstraction?

EoAs are now smart contracts. That's all account abstraction is.

But what does that mean?

Right now, every single transaction in web3 stems from a single private key. 

> account abstraction means that not only the execution of a transaction can be arbitrarily complex computation logic as specified by the EVM, but also the authorization logic.

- [Vitalik Buterin](https://ethereum-magicians.org/t/implementing-account-abstraction-as-part-of-eth1-x/4020)
- [EntryPoint Contract v0.6](https://etherscan.io/address/0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789)
- [EntryPoint Contract v0.7](https://etherscan.io/address/0x0000000071727De22E5E9d8BAf0edAc6f37da032)
- [zkSync AA Transaction Flow](https://docs.zksync.io/build/developer-reference/account-abstraction.html#the-transaction-flow)

## What's this repo show?

1. A minimal EVM "Smart Wallet" using alt-mempool AA
   1. We even send a transactoin to the `EntryPoint.sol`
2. A minimal zkSync "Smart Wallet" using native AA
   1. [zkSync uses native AA, which is slightly different than ERC-4337](https://docs.zksync.io/build/developer-reference/account-abstraction.html#iaccount-interface)
   2. We *do* send our zkSync transaction to the alt-mempool

## What does this repo not show?

1. Sending your userop to the alt-mempool 
   1. You can learn how to do this via the [alchemy docs](https://alchemy.com/?a=673c802981)

# Getting Started 

## Requirements

- [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
  - You'll know you did it right if you can run `git --version` and you see a response like `git version x.x.x`
- [foundry](https://getfoundry.sh/)
  - You'll know you did it right if you can run `forge --version` and you see a response like `forge 0.2.0 (816e00b 2023-03-16T00:05:26.396218Z)`
- [foundry-zksync](https://github.com/matter-labs/foundry-zksync)
  - You'll know you did it right if you can run `forge-zksync --help` and you see `zksync` somewhere in the output

## Installation

```bash
git clone https://github.com/PatrickAlphaC/minimal-account-abstraction
cd minimal-account-abstraction
make
```

# Quickstart 

## Vanilla Foundry

```bash
foundryup
make test
```

### Deploy - Arbitrum

```bash
make deployEth
```

### User operation - Arbitrum

```bash
make sendUserOp
```

## zkSync Foundry

```bash
foundryup-zksync
make zkbuild
make zktest
```

### Deploy - zkSync local network

#### Additional Requirements
- [npx & npm](https://docs.npmjs.com/cli/v10/commands/npm-install)
  - You'll know you did it right if you can run `npm --version` and you see a response like `7.24.0` and `npx --version` and you see a response like `8.1.0`.
- [yarn](https://classic.yarnpkg.com/lang/en/docs/install/#mac-stable)
  - You'll know you did it right if you can run `yarn --version` and you see a response like `1.22.17`.
- [docker](https://docs.docker.com/engine/install/)
  - You'll know you did it right if you can run `docker --version` and you see a response like `Docker version 20.10.7, build f0df350`.
  - Then, you'll want the daemon running, you'll know it's running if you can run `docker --info` and in the output you'll see something like the following to know it's running:
```bash
Client:
 Context:    default
 Debug Mode: false
```

Install dependencies:
```bash
yarn
```

#### Setup - local node

```bash
# Select `in memory node` and nothing else
npx zksync-cli dev start
```

#### Deploy - local node

> [!IMPORTANT]  
> *Never* have a private key associated with real funds in plaintext. 

```bash
# Setup your .env file, see the .env.example for an example
make zkdeploy
```

> Note: Sending an account abstraction transaction doesn't work on the local network, because we don't have the system contracts setup on the local network. 

### Deploy - zkSync Sepolia or Mainnet

Make sure your wallet has at least 0.01 zkSync ETH in it.

1. Encrypt your key 

Add your `PRIVATE_KEY` and `PRIVATE_KEY_PASSWORD` to your `.env` file, then run:

```bash
make encryptKey
```

> [!IMPORTANT]
> NOW DELETE YOUR PRIVATE KEY AND PASSWORD FROM YOUR `.env` FILE!!!
> Don't push your `.encryptedKey.json` up to GitHub either!

1. Un-Comment the Sepolia or Mainnet section (depending on which you'd like to use) of `DeployZkMinimal.ts` and `SendAATx.ts`:

```javascript
// // Sepolia - uncomment to use
```

3. Deploy the contract
```bash
make zkdeploy
```

You'll get an output like:
```
zkMinimalAccount deployed to: 0x4768d649Da9927a8b3842108117eC0ca7Bc6953f
With transaction hash: 0x103f6d894c20620dc632896799960d06ca37e722d20682ca824d428579ba157c
```

Grab the address of the `zkMinimalAccount` and add it to the `ZK_MINIMAL_ADDRESS` of `SendAATx.ts`.

4. Fund your account

Send it `0.002` zkSync sepolia ETH.

5. Send an AA transaction

```bash
make sendTx
```

You'll get an out put like this:

```
Let's do this!
Setting up contract details...
The owner of this minimal account is:  0x643315C9Be056cDEA171F4e7b2222a4ddaB9F88D
Populating transaction...
Signing transaction...
The minimal account nonce before the first tx is 0
Transaction sent from minimal account with hash 0xec7800e3a01d5ba5e472396127b656f7058cdcc5a1bd292b2b49f76aa19548c8
The account's nonce after the first tx is 1
```

# Example Deployments

## zkSync (Sepolia)
- [ZkMinimal Account (Sepolia)](https://sepolia.explorer.zksync.io/address/0xCB38Bdc1527c3F69E13701328546cA6FE23C5691)
- [USDC Approval via native zkSync AA (Sepolia)](https://sepolia.explorer.zksync.io/tx/0x43224b566a0b7497a26c57ab0fcea7d033dccd6cd6e16004523be0ce14fbd0fd)
- [Contract Deployer](https://explorer.zksync.io/address/0x0000000000000000000000000000000000008006)

## Ethereum (Arbitrum)
- [Minimal Account](https://arbiscan.io/address/0x03Ad95a54f02A40180D45D76789C448024145aaF#code)
- [USDC Approval via EntryPoint](https://arbiscan.io/tx/0x03f99078176ace63d36c5d7119f9f1c8a74da61516616c43593162ff34d1154b#eventlog)

# Account Abstraction zkSync Contract Deployment Flow

## First time
1. Calls `createAccount` or `create2Account` on the `CONTRACT_DEPLOYER` system contract 
   1. This will deploy the contract *to the L1*.
   2. Mark the contract hash in the `KnownCodesStorage` contract
   3. Mark it as an AA contract 
   4. [Example](https://sepolia.explorer.zksync.io/tx/0xec0d587903415b2785d542f8b41c21b82ad0613c226a8c83376ec2b8f90ffdd0#eventlog)
      1. Notice 6 logs emitted? 

## Subsequent times
1. Calls `createAccount` or `create2Account` on the `CONTRACT_DEPLOYER` system contract 
   1. The `CONTRACT_DEPLOYER` will check and see it's deployed this hash before
   2. It will put in another system contract that this address is associated with the first has
   3. [Example](https://sepolia.explorer.zksync.io/tx/0xe7a2a895d9854db5a6cc60df60524852d9957dd17adcc5720749f60b4da3eba7)
      1. Only 3 logs emitted!
   
# FAQ

## What if I don't add the contract hash to factory deps? 
The transaction will revert. The `ContractDeployer` checks to see if it knows the hash, and if not, it will revert! The `ContractDeployer` calls the `KnownCodesStorage` contract, which keeps track of *every single contract hash deployed on the zkSync chain. Crazy right!*

## Why can't we do these deployments with foundry or cast? 
Foundry and cast don't have support for the `factoryDeps` transaction field, or support for type `113` transactions. 

## Why can I use `forge create --legacy` to deploy a regular contract?
`foundry-zksync` is smart enough to see a legacy deployment (when you send a transaction to the 0 address with data) and transform it into a contract call to the deployer. It's only smart enough for legacy deployments as of today, not the new `EIP-1559` type 2 transactions or account creation.

# Acknowledgements 
- [Types of AAs on different chains](https://www.bundlebear.com/factories/all)
- [eth-infinitism](https://github.com/eth-infinitism/account-abstraction/)
- [Dan Nolan](https://www.youtube.com/watch?v=b4KWkIAPa3U)
  - [Twitter Video](https://x.com/BeingDanNolan/status/1795848790043218029)
- [zerodevapp](https://github.com/zerodevapp/kernel/)
- [Alchemy LightAccount](https://github.com/alchemyplatform/light-account/)

# Disclaimer
*This codebase is for educational purposes only and has not undergone a security review.*