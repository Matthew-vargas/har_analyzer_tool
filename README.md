# HAR Privacy Analyzer - Deployment Package

## 📁 Files Included

```
har-privacy-analyzer/
├── Dockerfile                          # Docker container configuration
├── har_analyzer_tool_backend.py        # Flask backend (Python)
├── har_analyzer_tool_frontend.html     # Web interface (HTML/CSS/JS)
└── RENDER_DEPLOYMENT_GUIDE.md          # Detailed deployment instructions
```

## 🚀 Quick Deploy to Render

1. **Create a Git repository** with these three files:
   - `Dockerfile`
   - `har_analyzer_tool_backend.py`
   - `har_analyzer_tool_frontend.html`

2. **Push to GitHub/GitLab**

3. **On Render.com**:
   - Click "New +" → "Web Service"
   - Connect your repository
   - Select **Docker** as environment
   - Click "Create Web Service"

4. **Done!** Render builds and deploys automatically.

See `RENDER_DEPLOYMENT_GUIDE.md` for detailed instructions.

---

## 🔧 Local Testing

```bash
# Build Docker image
docker build -t har-analyzer .

# Run container
docker run -p 5000:5000 har-analyzer

# Open in browser
http://localhost:5000
```

---

## 📋 What This App Does

Analyzes HAR (HTTP Archive) files to detect:
- 🔴 **Critical**: Meta/Facebook Pixel, TikTok Pixel
- 🟠 **High Risk**: LinkedIn Insight Tag
- 🔍 **Privacy Issues**: PII leakage, cross-site tracking
- 📊 **Analytics**: Third-party provider detection

---

## 💰 Hosting Costs

- **Free Tier**: $0/month (spins down after inactivity)
- **Starter**: $7/month (always on, recommended)

---

## ✅ Requirements

- Docker (for deployment)
- Python 3.11+ (for local development)
- Flask 3.0.0 (included in Dockerfile)

---

**Ready to deploy? See RENDER_DEPLOYMENT_GUIDE.md for step-by-step instructions.**
