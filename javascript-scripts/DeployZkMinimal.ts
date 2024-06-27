import * as fs from "fs-extra"
import { utils, Wallet, Provider, EIP712Signer, types, Contract, ContractFactory } from "zksync-ethers"
import * as ethers from "ethers"
import "dotenv/config"

async function main() {
    // Local net - comment to unuse
    // let provider = new Provider("http://127.0.0.1:8011")
    // let wallet = new Wallet(process.env.PRIVATE_KEY!)

    // Sepolia - uncomment to use
    let provider = new Provider(process.env.ZKSYNC_SEPOLIA_RPC_URL!)
    const encryptedJson = fs.readFileSync(".encryptedKey.json", "utf8")
    let wallet = Wallet.fromEncryptedJsonSync(
        encryptedJson,
        process.env.PRIVATE_KEY_PASSWORD!
    )

    // // Mainnet - uncomment to use
    // let provider = new Provider(process.env.ZKSYNC_RPC_URL!)
    // const encryptedJson = fs.readFileSync(".encryptedKey.json", "utf8")
    // let wallet = Wallet.fromEncryptedJsonSync(
    //     encryptedJson,
    //     process.env.PRIVATE_KEY_PASSWORD!
    // )

    wallet = wallet.connect(provider)
    console.log(`Working with wallet: ${await wallet.getAddress()}`)
    const abi = JSON.parse(fs.readFileSync("./out/ZkMinimalAccount.sol/ZkMinimalAccount.json", "utf8"))["abi"]
    const bytecode = JSON.parse(fs.readFileSync("./zkout/ZkMinimalAccount.sol/ZkMinimalAccount.json", "utf8"))["bytecode"]["object"]

    const factoryDeps = [bytecode] // We can skip this, but this is what's happening 
    const zkMinimalAccountFactory = new ContractFactory<any[], Contract>(
        abi,
        bytecode,
        wallet,
        "createAccount",
    )

    // const deployOptions = {
    //     customData: {
    //         salt: ethers.ZeroHash,
    //         // What if we don't do factoryDeps? 
    //         // factoryDeps,
    //         // factoryDeps: factoryDeps
    //         // Ah! The ContractFactory automatically adds it in!
    //     },
    // }

    const zkMinimalAccount = await zkMinimalAccountFactory.deploy()

    // The above should send the following calldata:
    // 0xecf95b8a0000000000000000000000000000000000000000000000000000000000000000010006ddf1eae1b53a0a62fab1fc8b4fd95c8a6f4d5fe540bf109f17bae0a431000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000
    // 
    // If you pop it into `calldata-decode` you'd see that the inputs to the `createAccount` are correct
    // cast calldata-decode "createAccount(bytes32,bytes32,bytes,uint8)" 

    console.log(`zkMinimalAccount deployed to: ${await zkMinimalAccount.getAddress()}`)
    console.log(`With transaction hash: ${(await zkMinimalAccount.deploymentTransaction())!.hash}`)
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error)
        process.exit(1)
    })