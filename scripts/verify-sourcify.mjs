import { readFile, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';

// Source verification only; this sends public source code and transaction hashes, never a key.
const deployment = JSON.parse(await readFile('deployments/sepolia.json', 'utf8'));
const results = [];
for (const [label, name] of [['resultSource', 'InterfoldResultSource'], ['demoNFT', 'DemoNFT'], ['auction', 'SealedBidAuction']]) {
  const address = deployment[label].address;
  const input = JSON.parse(execFileSync('forge', ['verify-contract', '--show-standard-json-input', '--chain', '11155111', address,
    `src/${name}.sol:${name}`], { encoding: 'utf8' }));
  const build = JSON.parse(await readFile(`out/${name}.sol/${name}.json`, 'utf8'));
  const metadata = typeof build.metadata === 'string' ? JSON.parse(build.metadata) : build.metadata;
  const payload = { stdJsonInput: input, compilerVersion: metadata.compiler.version,
    contractIdentifier: `src/${name}.sol:${name}`,
    creationTransactionHash: deployment.transactions.find(t => t.label === label).hash };
  const response = await fetch(`https://sourcify.dev/server/v2/verify/11155111/${address}`,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: AbortSignal.timeout(45000) });
  const body = await response.json();
  results.push({ label, address, status: response.status, submission: body,
    url: `https://repo.sourcify.dev/11155111/${address}` });
  console.log(JSON.stringify(results.at(-1)));
  await writeFile('deployments/source-verification.json', JSON.stringify(results, null, 2) + '\n');
}
