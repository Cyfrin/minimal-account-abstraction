import * as fs from "fs-extra"
import { utils, Wallet, Provider, EIP712Signer, types, Contract, ContractFactory } from "zksync-ethers"
import * as ethers from "ethers"
import "dotenv/config"

// Mainnet
// const ZK_MINIMAL_ADDRESS = ""

// Sepolia
// const ZK_MINIMAL_ADDRESS = ""

// Local
// Update this!
const ZK_MINIMAL_ADDRESS = "0x19a519025994A1F32188dE1F0E11014A791fB358"

// Update this too!
const RANDOM_APPROVER = "0x9EA9b0cc1919def1A3CfAEF4F7A66eE3c36F86fC"

// Mainnet
// const USDC_ZKSYNC = "0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4"
// Sepolia
const USDC_ZKSYNC = "0x5249Fd99f1C1aE9B04C65427257Fc3B8cD976620"

// Local
// let USDC_ZKSYNC = ""

const AMOUNT_TO_APPROVE = "1000000"

async function main() {
    console.log("Let's do this!")

    // Local net
    // let provider = new Provider("http://127.0.0.1:8011")
    // let wallet = new Wallet(process.env.PRIVATE_KEY!)

    // // Sepolia - Uncomment to use
    let provider = new Provider(process.env.ZKSYNC_SEPOLIA_RPC_URL!)
    const encryptedJson = fs.readFileSync(".encryptedKey.json", "utf8")
    let wallet = Wallet.fromEncryptedJsonSync(
        encryptedJson,
        process.env.PRIVATE_KEY_PASSWORD!
    )

    // // Mainnet - Uncomment to use
    // let provider = new Provider(process.env.ZKSYNC_RPC_URL!)
    // const encryptedJson = fs.readFileSync(".encryptedKey.json", "utf8")
    // let wallet = Wallet.fromEncryptedJsonSync(
    //     encryptedJson,
    //     process.env.PRIVATE_KEY_PASSWORD!
    // )

    wallet = wallet.connect(provider)

    const abi = JSON.parse(fs.readFileSync("./out/ZkMinimalAccount.sol/ZkMinimalAccount.json", "utf8"))["abi"]
    console.log("Setting up contract details...")
    const zkMinimalAccount = new Contract(ZK_MINIMAL_ADDRESS, abi, provider)

    // If this doesn't log the owner, you have an issue!
    console.log(`The owner of this minimal account is: `, await zkMinimalAccount.owner())
    const usdcAbi = JSON.parse(fs.readFileSync("./out/ERC20/IERC20.sol/IERC20.json", "utf8"))["abi"]
    const usdcContract = new Contract(USDC_ZKSYNC, usdcAbi, provider)

    console.log("Populating transaction...")
    let approvalData = await usdcContract.approve.populateTransaction(
        RANDOM_APPROVER,
        AMOUNT_TO_APPROVE
    )

    let aaTx = approvalData

    const gasLimit = await provider.estimateGas({
        ...aaTx,
        from: wallet.address,
    })
    const gasPrice = (await provider.getFeeData()).gasPrice!

    aaTx = {
        ...aaTx,
        from: ZK_MINIMAL_ADDRESS,
        gasLimit: gasLimit,
        gasPrice: gasPrice,
        chainId: (await provider.getNetwork()).chainId,
        nonce: await provider.getTransactionCount(ZK_MINIMAL_ADDRESS),
        type: 113,
        customData: {
            gasPerPubdata: utils.DEFAULT_GAS_PER_PUBDATA_LIMIT,
        } as types.Eip712Meta,
        value: 0n,
    }
    const signedTxHash = EIP712Signer.getSignedDigest(aaTx)

    console.log("Signing transaction...")
    const signature = ethers.concat([
        ethers.Signature.from(wallet.signingKey.sign(signedTxHash)).serialized,
    ])
    console.log(signature)

    aaTx.customData = {
        ...aaTx.customData,
        customSignature: signature,
    }

    console.log(
        `The minimal account nonce before the first tx is ${await provider.getTransactionCount(
            ZK_MINIMAL_ADDRESS,
        )}`,
    )

    const sentTx = await provider.broadcastTransaction(
        types.Transaction.from(aaTx).serialized,
    )

    console.log(`Transaction sent from minimal account with hash ${sentTx.hash}`)
    await sentTx.wait()

    // Checking that the nonce for the account has increased
    console.log(
        `The account's nonce after the first tx is ${await provider.getTransactionCount(
            ZK_MINIMAL_ADDRESS,
        )}`,
    )
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error)
        process.exit(1)
    })
