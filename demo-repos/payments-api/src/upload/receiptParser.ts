import archiveUtils from "archive-utils";
import lodash from "lodash";

export function parseReceiptArchive(buffer: Buffer) {
  const normalized = lodash.pick({ size: buffer.length, type: "receipt" }, ["size", "type"]);
  return archiveUtils.read(buffer, { strict: true, metadata: normalized });
}
