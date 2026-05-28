export async function saveReceiptMetadata(receiptId: string, metadata: unknown) {
  return { receiptId, metadata, saved: true };
}
