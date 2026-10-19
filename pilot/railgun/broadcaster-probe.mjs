// Read-only discovery. Importing this module never starts the wallet or Waku.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CHAIN_ID, CONTRACTS } from './config.mjs';
import { compatibleBroadcasterOffer, loadBroadcasterProbeConfig } from './broadcaster-config.mjs';

export async function probeBroadcasters(client, config, { timeoutMs = 35_000, sampleIntervalMs = 5000 } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 35_000
      || !Number.isSafeInteger(sampleIntervalMs) || sampleIntervalMs < 5 || sampleIntervalMs > 35_000) throw new Error('Invalid bounded broadcaster probe interval');
  const chain = { type: 0, id: CHAIN_ID }, started = Date.now(), states = [], samples = [];
  let timer, sampler, finished = false, diagnosticsErrors = 0;
  function inspect() {
    try {
      const all = client.findAllBroadcastersForChain(chain, true) ?? [];
      const weth = client.findBroadcastersForToken(chain, CONTRACTS.weth, true) ?? [];
      const eligible = weth.filter(offer => compatibleBroadcasterOffer(offer, config));
      return { all, eligible, connections: client.getWakuCore()?.libp2p?.getConnections?.().length ?? 0 };
    } catch { diagnosticsErrors++; return { all: [], eligible: [], connections: 0 }; }
  }
  return new Promise(resolveResult => {
    async function finish(result) {
      if (finished) return;
      finished = true; clearTimeout(timer); clearInterval(sampler);
      const inspected = inspect();
      // stop() emits Disconnected itself. Freeze observations before shutdown so
      // an orderly local stop cannot be mistaken for a failed network session.
      const report = { ...result, schemaVersion: 1, checkedAt: new Date().toISOString(), readOnly: true,
        broadcast: false, chain, durationMs: Date.now() - started, states: [...states],
        transport: { sdkStarted: client.isStarted(), connections: inspected.connections,
          contentTopics: [...client.getContentTopics()] },
        relayAdaptOffers: inspected.all.length, compatibleWethOffers: inspected.eligible.length,
        samples: [...samples], diagnosticsErrors, probeConfig: config,
        limitation: 'Authenticated SDK offer discovery only; it does not establish transaction acceptance, private-note spendability, or broadcaster independence. No wallet was opened and no transaction was constructed.' };
      try { await Promise.race([client.stop(), new Promise(resolve => setTimeout(resolve, 1000))]); } catch {}
      resolveResult(report);
    }
    function check() {
      if (finished) return;
      const info = inspect(), offer = info.eligible[0];
      if (offer) void finish({ ok: true, status: 'offer-discovered', offer: {
        railgunAddress: offer.railgunAddress, tokenAddress: offer.tokenAddress,
        feePerUnitGas: offer.tokenFee.feePerUnitGas, feesID: offer.tokenFee.feesID,
        relayAdapt: offer.tokenFee.relayAdapt, expiration: offer.tokenFee.expiration,
        availableWallets: offer.tokenFee.availableWallets,
      } });
    }
    timer = setTimeout(() => void finish({ ok: false, status: 'discovery-timeout',
      blocker: 'No usable Sepolia WETH broadcaster offer discovered within the bounded probe' }), timeoutMs);
    sampler = setInterval(() => {
      const info = inspect(); samples.push({ elapsedMs: Date.now() - started, connections: info.connections,
        relayAdaptOffers: info.all.length, compatibleWethOffers: info.eligible.length });
      check();
    }, sampleIntervalMs);
    try {
      client.setAddressFilters(config.broadcasterAllowlist, undefined);
      Promise.resolve(client.start(chain, config.sdkOptions, (_chain, status) => {
        if (!finished && states.length < 64) states.push(String(status));
        if (status === 'Connected') check();
      }, { log: () => {}, error: () => { diagnosticsErrors++; } }))
        .then(check).catch(() => void finish({ ok: false, status: 'client-error', blocker: 'Broadcaster client could not start; upstream details suppressed' }));
    } catch { void finish({ ok: false, status: 'client-error', blocker: 'Broadcaster client could not start; upstream details suppressed' }); }
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let configurationLoaded = false;
  try {
    const config = await loadBroadcasterProbeConfig(process.env.RAILGUN_BROADCASTER_CONFIG);
    configurationLoaded = true;
    const { WakuBroadcasterClient } = await import('@railgun-community/waku-broadcaster-client-node');
    console.log(JSON.stringify(await probeBroadcasters(WakuBroadcasterClient, config)));
  } catch (error) {
    // This CLI must never read a wallet in an error handler or echo upstream
    // requests/config contents. Its last stdout line remains preflight-compatible.
    const unsupportedPeers = !configurationLoaded && error.message === 'additionalDirectPeers is ignored by the pinned Node client; use a verified custom DNS discovery tree instead';
    console.log(JSON.stringify({ ok: false, status: configurationLoaded ? 'client-error' : 'configuration-error',
      blocker: unsupportedPeers ? error.message : configurationLoaded ? 'Broadcaster client failed; upstream details suppressed'
        : 'Invalid public broadcaster probe configuration; no discovery or transaction was started', readOnly: true, broadcast: false }));
  }
  process.exit(0); // Bound SDK background pollers after the completed probe.
}
