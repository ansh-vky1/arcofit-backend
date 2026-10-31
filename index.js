require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");
const axios = require("axios");

if (!admin.apps.length) {
  let serviceAccount;
  if (process.env.FIREBASE_SERVICE_ACCOUNT_B64) {
    serviceAccount = JSON.parse(
      Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_B64, "base64").toString("utf8")
    );
  } else {
    serviceAccount = {
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
    };
  }
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const ORIGINAL_PAISE = parseInt(process.env.ORIGINAL_PRICE_PAISE || "49900", 10);
const EXPIRY_EPOCH_SEC = parseInt(process.env.EXPIRY_EPOCH_SEC || "1802716199", 10);
const DODO_API_BASE = process.env.DODO_API_BASE || "https://test.dodopayments.com";
const DODO_API_KEY = process.env.DODO_API_KEY;

async function dodoRequest(method, path, body) {
  const res = await axios({
    method,
    url: `${DODO_API_BASE}${path}`,
    headers: {
      "Authorization": `Bearer ${DODO_API_KEY}`,
      "Content-Type": "application/json",
    },
    data: body,
  });
  return res.data;
}

const app = express();
app.use(cors({ origin: true }));
app.post("/webhook", express.raw({ type: "application/json" }), handleWebhook);
app.use(express.json({ limit: "1mb" }));

async function requireAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: "missing auth token" });
    const decoded = await admin.auth().verifyIdToken(token);
    req.uid = decoded.uid;
    req.email = decoded.email || "";
    req.name = decoded.name || "";
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid auth token", detail: String(e.message || e) });
  }
}

app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now(), provider: "dodo" }));

app.post("/create-order", requireAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const rawCode = (req.body.promoCode || "").toString().trim().toUpperCase();
    const code = rawCode || null;

    let discountPaise = 0, promoCodeId = null, creatorId = null, creatorName = null;
    let commissionRateBps = 0, allowFree = false;

    if (code) {
      const snap = await db.collection("promoCodes")
        .where("code", "==", code).where("active", "==", true).limit(1).get();
      if (snap.empty) return res.status(400).json({ error: "invalid or inactive promo code" });
      const pdoc = snap.docs[0];
      promoCodeId = pdoc.id;
      const pd = pdoc.data();
      discountPaise = Math.min((pd.discountRupees || 0) * 100, ORIGINAL_PAISE);
      allowFree = !!pd.allowFree;
      creatorId = pd.creatorId || null;
      creatorName = pd.creatorName || null;
      if (creatorId) {
        const cSnap = await db.collection("creators").doc(creatorId).get();
        if (cSnap.exists) commissionRateBps = cSnap.data().commissionRateBps || 0;
      }
    }

    const paidPaise = Math.max(0, ORIGINAL_PAISE - discountPaise);
    if (paidPaise === 0 && !allowFree) return res.status(400).json({ error: "free access code is not enabled" });

    if (paidPaise === 0) {
      const purchaseId = `free_${uid}_${Date.now()}`;
      const now = admin.firestore.Timestamp.now();
      await db.collection("purchases").doc(purchaseId).set({
        uid, email: req.email, displayName: req.name, registeredAt: now,
        creatorId, creatorName, promoCode: code, promoCodeId, commissionRateBps,
        originalPaise: ORIGINAL_PAISE, discountPaise: ORIGINAL_PAISE, paidPaise: 0,
        status: "paid", commissionPaise: 0, payoutStatus: "pending", payoutId: null,
        purchasedAt: now, createdAt: now,
      });
      await grantEntitlement(uid, purchaseId);
      return res.json({ orderId: purchaseId, payablePaise: 0, free: true });
    }

    const purchaseId = `p_${uid.slice(0, 6)}_${Date.now()}`;
    const now = admin.firestore.Timestamp.now();

    const dodoSession = await dodoRequest("POST", "/checkouts", {
      product_cart: [{ product_id: process.env.DODO_PRODUCT_ID, quantity: 1 }],
      customer: { email: req.email, name: req.name },
      metadata: { uid, purchaseId, promoCode: code || "" },
      return_url: `arcofit://payment-success?purchaseId=${purchaseId}`,
      cancel_url: `arcofit://payment-cancelled?purchaseId=${purchaseId}`,
    });

    await db.collection("purchases").doc(purchaseId).set({
      uid, email: req.email, displayName: req.name, registeredAt: now,
      creatorId, creatorName, promoCode: code, promoCodeId, commissionRateBps,
      originalPaise: ORIGINAL_PAISE, discountPaise, paidPaise,
      dodoCheckoutId: dodoSession.session_id || purchaseId,
      dodoPaymentId: null,
      status: "created", commissionPaise: 0, payoutStatus: "pending", payoutId: null,
      purchasedAt: null, createdAt: now,
    });

    return res.json({
      orderId: purchaseId,
      checkoutUrl: dodoSession.checkout_url,
      originalPaise: ORIGINAL_PAISE,
      discountPaise,
      payablePaise: paidPaise,
    });
  } catch (e) {
    console.error("create-order error", e.response?.data || e);
    return res.status(500).json({ error: "create-order failed", detail: String(e.message || e) });
  }
});

async function handleWebhook(req, res) {
  try {
    const secret = process.env.DODO_WEBHOOK_SECRET;
    const sig = req.headers["webhook-signature"] || req.headers["x-webhook-signature"];
    const body = req.body.toString("utf8");
    const expected = crypto.createHmac("sha256", secret).update(body).digest("hex");
    if (sig && sig !== expected) {
      console.error("webhook signature mismatch");
      return res.status(400).send("bad signature");
    }

    const evt = JSON.parse(body);
    const eventType = evt.type || evt.event;
    console.log("webhook event:", eventType);

    if (eventType === "payment.succeeded" || eventType === "payment.completed") {
      const meta = evt.data?.metadata || {};
      const uid = meta.uid;
      const purchaseId = meta.purchaseId;
      const paymentId = evt.data?.payment_id || evt.data?.id;

      if (uid && purchaseId) {
        const ref = db.collection("purchases").doc(purchaseId);
        await db.runTransaction(async (tx) => {
          const snap = await tx.get(ref);
          if (!snap.exists) return;
          if (snap.data().status === "paid") return;
          const p = snap.data();
          const commissionPaise = p.creatorId ? Math.round((p.paidPaise * p.commissionRateBps) / 10000) : 0;
          tx.update(ref, {
            dodoPaymentId: paymentId, status: "paid", commissionPaise,
            purchasedAt: admin.firestore.Timestamp.now(),
          });
          if (p.promoCodeId) {
            tx.update(db.collection("promoCodes").doc(p.promoCodeId), {
              usageCount: admin.firestore.FieldValue.increment(1),
            });
          }
          if (p.creatorId) {
            tx.update(db.collection("creators").doc(p.creatorId), {
              "totals.salesCount": admin.firestore.FieldValue.increment(1),
              "totals.grossPaise": admin.firestore.FieldValue.increment(p.paidPaise),
              "totals.commissionPaise": admin.firestore.FieldValue.increment(commissionPaise),
            });
          }
        });
        await grantEntitlement(uid, purchaseId);
      }
    }
    return res.status(200).send("ok");
  } catch (e) {
    console.error("webhook error", e);
    return res.status(500).send("error");
  }
}

async function grantEntitlement(uid, purchaseId) {
  await db.collection("users").doc(uid).set({
    entitlement: {
      active: true, expSec: EXPIRY_EPOCH_SEC, entitlementId: purchaseId,
      updatedAt: admin.firestore.Timestamp.now(),
    },
  }, { merge: true });
}

app.get("/entitlement", requireAuth, async (req, res) => {
  try {
    const snap = await db.collection("users").doc(req.uid).get();
    const ent = snap.data()?.entitlement;
    if (!ent?.active) return res.status(404).json({ error: "no purchase found" });
    return res.json({ entitlementId: ent.entitlementId, expSec: ent.expSec });
  } catch (e) {
    return res.status(500).json({ error: "entitlement fetch failed", detail: String(e.message || e) });
  }
});

app.post("/check-status", requireAuth, async (req, res) => {
  try {
    const { purchaseId } = req.body;
    if (!purchaseId) return res.status(400).json({ error: "purchaseId required" });
    const snap = await db.collection("purchases").doc(purchaseId).get();
    if (!snap.exists) return res.status(404).json({ error: "not found" });
    const d = snap.data();
    if (d.uid !== req.uid) return res.status(403).json({ error: "wrong user" });
    return res.json({ status: d.status, paidPaise: d.paidPaise });
  } catch (e) {
    return res.status(500).json({ error: "check failed", detail: String(e.message || e) });
  }
});

const PORT = parseInt(process.env.PORT || "3000", 10);
app.listen(PORT, () => {
  console.log(`ArcoFit backend (Dodo) listening on port ${PORT}`);
  console.log(`DODO_API_KEY set: ${!!process.env.DODO_API_KEY}`);
  console.log(`FIREBASE_PROJECT_ID: ${process.env.FIREBASE_PROJECT_ID}`);
});
