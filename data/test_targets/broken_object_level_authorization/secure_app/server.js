/*
 * Fixture SICURA per il rilevatore statico API1 (BOLA) — servizio Express.
 * Nessun handler deve produrre finding (FPR = 0%).
 */
const express = require("express");
const { authenticate, requireAdmin } = require("./middleware");
const { Order, Document, Project, Task, User } = require("./models");

const app = express();
const router = express.Router();
app.use(express.json());

const invoices = [];
const receipts = [];

router.get("/orders/:orderId", authenticate, async (req, res) => {
  const order = await Order.findOne({ _id: req.params.orderId, owner: req.user.id });
  if (!order) return res.sendStatus(404);
  res.json(order);
});

router.get("/invoices/:invoiceId", authenticate, (req, res) => {
  const invoice = invoices.find(
    (i) => i.id === req.params.invoiceId && i.ownerId === req.user.id
  );
  if (!invoice) return res.sendStatus(404);
  res.json(invoice);
});

router.get("/documents/:docId", authenticate, async (req, res) => {
  const doc = await Document.findOne({ _id: req.params.docId, owner: req.user.id });
  if (!doc) return res.sendStatus(404);
  res.json(doc);
});

router.put("/documents/:docId", authenticate, async (req, res) => {
  const doc = await Document.findOneAndUpdate(
    { _id: req.params.docId, owner: req.user.id },
    req.body,
    { new: true }
  );
  if (!doc) return res.sendStatus(404);
  res.json(doc);
});

router.get("/projects/:projectId/tasks/:taskId", authenticate, async (req, res) => {
  const project = await Project.findById(req.params.projectId);
  if (!project || project.ownerId !== req.user.id) {
    return res.sendStatus(403);
  }
  const task = await Task.findOne({ _id: req.params.taskId, project: project._id });
  if (!task) return res.sendStatus(404);
  res.json(task);
});

router.get("/receipts/:receiptId(\\d+)", authenticate, (req, res) => {
  const receipt = receipts.find(
    (r) => r.id === Number(req.params.receiptId) && r.userId === req.user.id
  );
  if (!receipt) return res.sendStatus(404);
  res.json(receipt);
});

router.get("/profiles/:userId", authenticate, async (req, res) => {
  const { userId } = req.params;
  if (userId !== req.user.id) return res.sendStatus(403);
  const user = await User.findById(userId);
  res.json(user);
});

router.delete("/admin/users/:userId(\\d+)", authenticate, requireAdmin, async (req, res) => {
  await User.destroy({ where: { id: Number(req.params.userId) } });
  res.sendStatus(204);
});

app.use("/api", router);
module.exports = app;
