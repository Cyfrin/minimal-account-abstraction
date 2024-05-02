*Note: This repo is not complete and a work in progress*

# Account Abstraction

- [Account Abstraction](#account-abstraction)
  - [What is Account Abstraction?](#what-is-account-abstraction)
  - [What's this repo show?](#whats-this-repo-show)
  - [What does this repo not show?](#what-does-this-repo-not-show)
- [Getting Started](#getting-started)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Quickstart](#quickstart)
- [Example Deployments](#example-deployments)
  - [zkSync](#zksync)
  - [Ethereum (Arbitrum)](#ethereum-arbitrum)
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

## Quickstart 

```bash
make test
```

# Example Deployments

## zkSync
- TODO

## Ethereum (Arbitrum)
- [Minimal Account](https://arbiscan.io/address/0x03Ad95a54f02A40180D45D76789C448024145aaF#code)
- [USDC Approval via EntryPoint](https://arbiscan.io/tx/0x03f99078176ace63d36c5d7119f9f1c8a74da61516616c43593162ff34d1154b#eventlog)

# Acknowledgements 
- [Types of AAs on different chains](https://www.bundlebear.com/factories/all)
- [eth-infinitism](https://github.com/eth-infinitism/account-abstraction/)
- [Dan Nolan](https://www.youtube.com/watch?v=b4KWkIAPa3U)
- [zerodevapp](https://github.com/zerodevapp/kernel/)
- [Alchemy LightAccount](https://github.com/alchemyplatform/light-account/)

# Disclaimer
*This codebase is for educational purposes only and has not undergone a security review.*