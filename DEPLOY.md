# Deploying UPI Scam Pattern Checker — Live Link Guide

Goal: end up with a real URL you can put on your resume, instead of "clone and run locally."

Two pieces to deploy:
- **Backend** (Flask API) → Render, using Docker (handles the QR-decode system dependency reliably)
- **Frontend** (static HTML) → Netlify (drag-and-drop, no build step needed)

Total time: ~20-30 minutes, both have free tiers.

---

## Part 1 — Push your code to GitHub

Deployment platforms pull from a GitHub repo, so this has to happen first.

1. Create a new repo on GitHub (e.g. `upi-scam-checker`) — public is fine and actually better, recruiters can see the code.
2. In your project folder (the one with `backend/` and `frontend/`):
   ```bash
   git init
   git add .
   git commit -m "Initial commit: UPI scam pattern checker"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/upi-scam-checker.git
   git push -u origin main
   ```
3. Add a `.gitignore` in the project root so you don't commit junk:
   ```
   __pycache__/
   *.pyc
   scan_history.db
   feedback_log.jsonl
   ```

---

## Part 2 — Deploy the backend on Render

1. Go to **render.com**, sign up (GitHub login is fastest).
2. Click **New +** → **Web Service**.
3. Connect your GitHub repo, select `upi-scam-checker`.
4. Render will detect the `Dockerfile` in `backend/` — set:
   - **Root Directory:** `backend`
   - **Environment:** Docker (should auto-detect from the Dockerfile)
   - **Instance Type:** Free
5. Under **Environment Variables**, add:
   - `FRONTEND_ORIGIN` = (leave blank for now, you'll set this after Part 3, once you know your Netlify URL — e.g. `https://upi-scam-checker.netlify.app`)
6. Click **Create Web Service**. First deploy takes a few minutes (it's building the Docker image).
7. Once live, Render gives you a URL like `https://upi-scam-checker-xxxx.onrender.com`. Test it:
   ```bash
   curl https://upi-scam-checker-xxxx.onrender.com/api/health
   ```
   Should return `{"status": "ok"}`.

**Free tier note:** Render's free web services spin down after 15 minutes of no traffic and take ~30-50 seconds to wake up on the next request. Fine for a resume demo link, just know the first click might feel slow — worth mentioning to whoever's testing it, or add a small "waking up the server, give it a moment" note near your live link.

---

## Part 3 — Deploy the frontend on Netlify

1. Before deploying, edit `frontend/index.html` — find this line near the top of the `<script>` block:
   ```js
   const API_BASE = "http://localhost:5000/api";
   ```
   Replace with your actual Render URL:
   ```js
   const API_BASE = "https://upi-scam-checker-xxxx.onrender.com/api";
   ```
2. Go to **netlify.com**, sign up.
3. Drag the `frontend` folder directly onto the Netlify dashboard (the area that says "Drag and drop your site output folder here"). No build step needed since it's plain HTML.
4. Netlify gives you a URL like `https://random-name-123.netlify.app`. You can rename it under **Site settings → Change site name** to something like `upi-scam-checker.netlify.app`.

---

## Part 4 — Connect the two (CORS)

Go back to Render → your backend service → **Environment** → set:
```
FRONTEND_ORIGIN = https://upi-scam-checker.netlify.app
```
(use your actual Netlify URL). Save — Render will redeploy automatically. This restricts your API to only accept requests from your deployed frontend, which is the correct production setup rather than leaving it wide open.

---

## Part 5 — Verify end-to-end

Open your Netlify URL in a browser, run a scan. If you get a "could not reach backend" error:
- Check the Render service is awake (visit the `/api/health` URL directly first to wake it up)
- Check `API_BASE` in your deployed `index.html` matches your Render URL exactly (including `/api` at the end)
- Check `FRONTEND_ORIGIN` on Render matches your Netlify URL exactly (no trailing slash)

---

## What to put on your resume

Something like:
> UPI Scam Pattern Checker — rule-based fraud detection tool with QR decoding, batch scanning, and repeated-payment pattern correlation. [Live demo] · [GitHub]

Both links working is what makes this land — a project a recruiter can actually click and try beats a screenshot every time.
