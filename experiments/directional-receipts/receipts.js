/** Fail-first boundary only. No controller, receipt issuance or accounting exists yet. */
export function openDirectionalLedger(_path) {
  return {
    counters(_communityId, _cohortId, _memberId) {
      return { authorizedSend: 0, acknowledgedReceive: 0 };
    },
    counts() { return { authorizations: 0, lifetimeNullifiers: 0, redeemedReceipts: 0 }; },
    prune(_now) {},
    close() {},
  };
}

export function createDirectionalService(_options) {
  return {
    async authorizeAndAcknowledge(_request) {
      throw new Error('Directional receipt issuance is not implemented');
    },
    async redeemAcknowledgedReceipt(_request) { return false; },
  };
}
