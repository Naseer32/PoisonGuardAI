// The ONLY module that talks to the GenLayer SDK and the wallet. Everything the SDK is expected to provide is
// listed here, in one place, so a mismatch with your installed SDK version is a one-file fix.
//
// Expected genlayer-js surface (loaded from PG_SDK_URL, verified at runtime by describeSdk):
//   createClient({ chain, account?, endpoint? }) -> client with
//     readContract({ address, functionName, args })            -> decoded value (dicts may be Map, ints may be bigint)
//     writeContract({ address, functionName, args, value })    -> transaction hash
//     getTransaction({ hash })                                 -> transaction object
//   chains exported from "<sdk>/chains" (or the main module), selected by PG_CHAIN_KEY.
import schema from "./contract-schema.js";
import { normalize } from "./normalize.js";

export class AppError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = "AppError";
    this.code = code;
    Object.assign(this, extra);
  }
}

let sdkCache = null;
export const resetSdkCache = () => { sdkCache = null; };

export async function loadSdk(cfg, importer = (u) => import(/* webpackIgnore: true */ u)) {
  if (sdkCache) return sdkCache;
  if (!cfg.sdkUrl) throw new AppError("SDK_URL", "PG_SDK_URL is not set");
  let main;
  try { main = await importer(cfg.sdkUrl); }
  catch (e) { throw new AppError("SDK_LOAD", "Could not load the GenLayer SDK from " + cfg.sdkUrl + ": " + (e && e.message ? e.message : e)); }
  const optional = async (sub) => { try { return await importer(cfg.sdkUrl + sub); } catch { return null; } };
  sdkCache = { main, chains: await optional("/chains"), types: await optional("/types") };
  return sdkCache;
}

const isChain = (x) => x && typeof x === "object" && "id" in x;

export function describeSdk(sdk) {
  const pool = { ...(sdk.main || {}), ...(sdk.chains || {}) };
  return {
    hasCreateClient: typeof (sdk.main && sdk.main.createClient) === "function",
    chainKeys: Object.keys(pool).filter((k) => isChain(pool[k])),
    hasTransactionStatus: Boolean((sdk.types && sdk.types.TransactionStatus) || (sdk.main && sdk.main.TransactionStatus)),
  };
}

export function resolveChain(sdk, cfg) {
  const info = describeSdk(sdk);
  if (!info.hasCreateClient) throw new AppError("SDK_SHAPE", "The loaded SDK has no createClient(). Check PG_SDK_URL and version.");
  const chain = (sdk.chains && sdk.chains[cfg.chainKey]) || (sdk.main && sdk.main[cfg.chainKey]);
  if (!isChain(chain))
    throw new AppError("CHAIN_NOT_FOUND", 'The SDK exports no chain named "' + cfg.chainKey + '". Chains it does export: ' + (info.chainKeys.join(", ") || "none found") + ". Set PG_CHAIN_KEY to one of them.");
  return chain;
}

const options = (cfg, chain, account) => ({ chain, ...(account ? { account } : {}), ...(cfg.rpcUrl ? { endpoint: cfg.rpcUrl } : {}) });

export const makeReadClient = (sdk, cfg, chain) => sdk.main.createClient(options(cfg, chain));

export async function ensureChain(eth, chain) {
  if (chain.id == null) throw new AppError("CHAIN_ID", "The SDK chain has no id");
  const chainId = "0x" + Number(chain.id).toString(16);
  try {
    await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId }] });
  } catch (e) {
    if (!(e && (e.code === 4902 || /unrecognized chain|not added|unknown chain/i.test(String(e.message))))) throw e;
    const urls = chain.rpcUrls && chain.rpcUrls.default && chain.rpcUrls.default.http;
    const explorer = chain.blockExplorers && chain.blockExplorers.default && chain.blockExplorers.default.url;
    await eth.request({
      method: "wallet_addEthereumChain",
      params: [{ chainId, chainName: chain.name, nativeCurrency: chain.nativeCurrency, rpcUrls: urls || [], ...(explorer ? { blockExplorerUrls: [explorer] } : {}) }],
    });
  }
}

export async function connectWallet(sdk, cfg, chain, eth) {
  if (!eth) throw new AppError("NO_WALLET", "No browser wallet found. Open this page in a wallet browser (for example MetaMask mobile) or install a wallet extension.");
  const accounts = await eth.request({ method: "eth_requestAccounts" });
  const account = Array.isArray(accounts) ? accounts[0] : null;
  if (!account) throw new AppError("NO_ACCOUNT", "The wallet returned no account");
  await ensureChain(eth, chain);
  const client = sdk.main.createClient(options(cfg, chain, account));
  const walletChainId = await eth.request({ method: "eth_chainId" });
  return { account, client, walletChainId: Number(walletChainId), chainMatches: Number(walletChainId) === Number(chain.id) };
}

function assertCall(name, kind, args) {
  const m = schema.methods[name];
  if (!m) throw new AppError("NO_METHOD", "The contract schema has no method " + name);
  if (m.kind !== kind) throw new AppError("WRONG_KIND", name + " is a " + m.kind + " method, not " + kind);
  if (!Array.isArray(args) || args.length !== m.params.length) throw new AppError("BAD_ARGS", name + " expects " + m.params.length + " arguments");
}

export async function readView(client, cfg, name, args = []) {
  assertCall(name, "view", args);
  return normalize(await client.readContract({ address: cfg.contractAddress, functionName: name, args }));
}

export async function sendWrite(wallet, cfg, name, args) {
  assertCall(name, "write", args);
  const hash = await wallet.client.writeContract({ address: cfg.contractAddress, functionName: name, args, value: 0n });
  if (typeof hash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new AppError("BAD_HASH", "The SDK returned no valid transaction hash, so the transaction cannot be tracked", { hash });
  return hash;
}

export const fetchTransaction = (client, hash) => client.getTransaction({ hash });
