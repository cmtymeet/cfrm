/** Fail-first release-attestation boundary. No signatures or counter mutations yet. */
export function createReleaseReceiptService(_options) {
  return {
    async authorizeAndAcknowledge(_request) {
      throw new Error('Counter-backed sender attestation is not implemented');
    },
    async redeemAcknowledgedReceipt(_request) { return false; },
  };
}
