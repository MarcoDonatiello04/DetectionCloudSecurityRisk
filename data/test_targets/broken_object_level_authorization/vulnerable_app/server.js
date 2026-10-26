/*
 * Fixture VULNERABILE per il rilevatore statico API1 (BOLA) — servizio Express.
 * Stessi casi della versione Flask; ground truth in
 * tests/unit/api1_bola/validate_static_ground_truth.py.
 */
const express = require("express");
const { authenticate, requireAdmin } = require("./middleware");
const { Order, Document, Project, Task, User } = require("./models");

const app = express();
const router = express.Router();
app.use(express.json());

const invoices = [];
const receipts = [];

// OA-001: autenticato, ma l'ordine è recuperato solo per ID
router.get("/orders/:orderId", authenticate, async (req, res) => {
  const order = await Order.findById(req.params.orderId);
  res.json(order);
});

// OA-002: nessuna guardia e nessuna identità prima dell'accesso
router.get("/invoices/:invoiceId", (req, res) => {
  const invoice = invoices.find((i) => i.id === req.params.invoiceId);
  if (!invoice) return res.sendStatus(404);
  res.json(invoice);
});

// Riferimento per OA-003: la lettura è filtrata sull'owner...
router.get("/documents/:docId", authenticate, async (req, res) => {
  const doc = await Document.findOne({ _id: req.params.docId, owner: req.user.id });
  if (!doc) return res.sendStatus(404);
  res.json(doc);
});

// OA-003: ...la modifica dello stesso documento no
router.put("/documents/:docId", authenticate, async (req, res) => {
  const doc = await Document.findByIdAndUpdate(req.params.docId, req.body, { new: true });
  res.json(doc);
});

// OA-004: il progetto è validato contro l'owner, il task no
router.get("/projects/:projectId/tasks/:taskId", authenticate, async (req, res) => {
  const project = await Project.findById(req.params.projectId);
  if (!project || project.ownerId !== req.user.id) {
    return res.sendStatus(403);
  }
  const task = await Task.findById(req.params.taskId);
  res.json(task);
});

// OA-005 (+ OA-002): ID intero sequenziale, nessuna guardia di autenticazione
router.get("/receipts/:receiptId(\\d+)", (req, res) => {
  const receipt = receipts[Number(req.params.receiptId)];
  res.json(receipt);
});

// Controllo negativo: l'ID di path è confrontato con l'identità
router.get("/profiles/:userId", authenticate, async (req, res) => {
  const { userId } = req.params;
  if (userId !== req.user.id) return res.sendStatus(403);
  const user = await User.findById(userId);
  res.json(user);
});

// Controllo negativo: endpoint amministrativo (dominio API5, non BOLA)
router.delete("/admin/users/:userId(\\d+)", authenticate, requireAdmin, async (req, res) => {
  await User.destroy({ where: { id: Number(req.params.userId) } });
  res.sendStatus(204);
});

app.use("/api", router);
module.exports = app;
