import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { Contract, formatEther, id } from 'ethers';
import { sepoliaProvider, PROTOCOL, DEPLOYER, protocolAbi, CHAIN_ID } from './config.mjs';

const provider = await sepoliaProvider();
const protocol = new Contract(PROTOCOL, protocolAbi, provider);
const [blockNumber, balance, paused, owner, feeToken, ciphertextVerifier] = await Promise.all([
  provider.getBlockNumber(), provider.getBalance(DEPLOYER), protocol.requestsPaused(),
  protocol.owner(), protocol.feeToken(), protocol.getCiphertextVerifier(id('fhe.rs:BFV')),
]);
const report = {
  checkedAt: new Date().toISOString(), chainId: CHAIN_ID, blockNumber,
  wallet: DEPLOYER, balanceEth: formatEther(balance), interfold: PROTOCOL,
  requestsPaused: paused, owner, feeToken, ciphertextVerifier,
  programRegistration: 'Requires Interfold owner; not requested automatically.',
  pilotStatus: 'Local secure-BFV and program gate implemented; full input/compute/DA proof integration and owner registration remain unavailable.',
};
try {
  const deployment = JSON.parse(await readFile('deployments/sepolia.json', 'utf8'));
  if (deployment.resultSource?.address) {
    const source = new Contract(deployment.resultSource.address,
      ['function program() view returns(address)', 'function isReady() view returns(bool)'], provider);
    report.pilot = { resultSource: deployment.resultSource.address,
      program: await source.program(), ready: await source.isReady() };
  }
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
await mkdir('deployments', { recursive: true });
await writeFile('deployments/preflight-sepolia.json', JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
provider.destroy();
