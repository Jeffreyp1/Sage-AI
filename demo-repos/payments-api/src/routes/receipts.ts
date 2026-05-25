import express from "express";
import { parseReceiptArchive } from "../upload/receiptParser";

const router = express.Router();

router.post("/api/receipts/upload", async (request, response) => {
  const parsed = parseReceiptArchive(request.body);
  response.json({ ok: true, receiptCount: parsed.files.length });
});

export default router;

