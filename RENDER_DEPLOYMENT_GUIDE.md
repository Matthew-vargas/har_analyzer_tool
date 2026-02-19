# Render Deployment Guide - HAR Privacy Analyzer

## 📦 Files Required for Deployment

Your deployment package includes:
- `Dockerfile` - Container configuration
- `har_analyzer_tool_backend.py` - Flask backend application
- `har_analyzer_tool_frontend.html` - Frontend HTML interface

---

## 🚀 Deployment Steps on Render

### 1. Prepare Your Repository

**Option A: Using Git Repository (Recommended)**

1. Create a new Git repository:
   ```bash
   mkdir har-privacy-analyzer
   cd har-privacy-analyzer
   git init
   ```

2. Copy the three files into your repository:
   - `Dockerfile`
   - `har_analyzer_tool_backend.py`
   - `har_analyzer_tool_frontend.html`

3. Commit and push to GitHub/GitLab:
   ```bash
   git add .
   git commit -m "Initial commit"
   git remote add origin <your-repo-url>
   git push -u origin main
   ```

**Option B: Manual Upload**
- You can also upload files directly through Render's dashboard

---

### 2. Create Web Service on Render

1. **Log in to Render**: https://render.com

2. **Click "New +"** → Select **"Web Service"**

3. **Connect Repository**:
   - If using Git: Connect your GitHub/GitLab repository
   - If manual: Choose "Deploy an existing image from a registry" (after building locally)

4. **Configure Service**:

   **Name**: `har-privacy-analyzer` (or your preferred name)
   
   **Region**: Choose closest to your users
   
   **Branch**: `main` (or your default branch)
   
   **Root Directory**: Leave blank (unless files are in a subdirectory)
   
   **Environment**: `Docker`
   
   **Instance Type**: 
   - **Free tier**: Select "Free" (will spin down after inactivity)
   - **Paid tier**: Select "Starter" or higher for always-on service ($7/month)

5. **Advanced Settings** (Optional):
   - **Auto-Deploy**: Enable (recommended) - deploys automatically on git push
   - **Health Check Path**: `/` (verifies the app is running)

6. **Click "Create Web Service"**

---

### 3. Deployment Process

Render will automatically:
1. Pull your repository
2. Build the Docker image from your Dockerfile
3. Start the container
4. Assign a public URL (e.g., `https://har-privacy-analyzer.onrender.com`)

**Build time**: ~2-3 minutes

---

## ✅ Verify Deployment

Once deployed, you'll receive a URL like:
```
https://your-app-name.onrender.com
```

**Test your deployment:**
1. Visit the URL in your browser
2. Upload a HAR file
3. Verify the analysis results display correctly
4. Check that Meta/TikTok/LinkedIn alerts appear if present in the HAR

---

## 🔧 Configuration Details

### Port Configuration
- The app automatically uses Render's `PORT` environment variable
- Default: 5000 (for local testing)
- Render overrides this automatically in production

### Debug Mode
- **Disabled in production** (debug=False)
- Enabled in `__main__` for local development

### File Storage
- HAR files are processed in memory (no persistent storage needed)
- Frontend served from `/static` directory

---

## 📊 Resource Usage

**Free Tier Limitations:**
- 750 hours/month (25 hours/day shared across all free services)
- Service spins down after 15 minutes of inactivity
- Cold start: ~30 seconds to wake up
- **Sufficient for**: Testing, demos, low-traffic use

**Starter Tier ($7/month):**
- Always on (no spin down)
- Instant response times
- 512 MB RAM, 0.5 CPU
- **Recommended for**: Production use

---

## 🔒 Security Considerations

### Current Setup:
- ✅ No persistent file storage (HAR files processed in memory)
- ✅ Debug mode disabled in production
- ✅ No database (stateless application)
- ✅ HTTPS enabled by default on Render

### Optional Enhancements:
- Add rate limiting for API endpoints
- Implement request size limits
- Add CORS headers if building API
- Enable Render's DDoS protection (paid plans)

---

## 🛠️ Troubleshooting

### Build Fails
**Issue**: Docker build errors
**Solution**: 
- Check that all three files are in repository root
- Verify Dockerfile syntax
- Check Render build logs for specific error

### App Won't Start
**Issue**: Container starts but app crashes
**Solution**:
- Check Render logs: Dashboard → Your Service → Logs
- Verify `har_analyzer_tool_frontend.html` is in `static/` directory
- Ensure Flask is installed (should be in Dockerfile)

### 502 Bad Gateway
**Issue**: Service not responding
**Solution**:
- Check that port binding uses `0.0.0.0` (already configured)
- Verify `PORT` environment variable is being used
- Check logs for startup errors

### Frontend Not Loading
**Issue**: Index page returns 404
**Solution**:
- Verify `static/har_analyzer_tool_frontend.html` exists in container
- Check Dockerfile copies frontend correctly
- View logs for "FileNotFoundError"

---

## 📝 Local Testing Before Deployment

Test the Docker container locally before deploying:

```bash
# Build the Docker image
docker build -t har-analyzer .

# Run the container
docker run -p 5000:5000 har-analyzer

# Test in browser
open http://localhost:5000
```

---

## 🔄 Updating Your Deployment

### Automatic Updates (if Auto-Deploy enabled):
```bash
# Make changes to your code
git add .
git commit -m "Update: description of changes"
git push

# Render automatically rebuilds and deploys
```

### Manual Deploy:
1. Go to Render Dashboard
2. Click your service
3. Click "Manual Deploy" → "Deploy latest commit"

---

## 📈 Monitoring

**Render Dashboard provides:**
- Real-time logs
- CPU and memory usage
- Request metrics
- Uptime monitoring
- Email alerts for crashes

**Access logs:**
```
Dashboard → Your Service → Logs
```

---

## 💰 Cost Estimate

### Free Tier:
- **Cost**: $0/month
- **Use case**: Testing, demos, personal projects
- **Limitation**: Spins down after inactivity

### Starter Tier:
- **Cost**: $7/month
- **Use case**: Small production deployments
- **Features**: Always on, faster performance

### Professional Tier:
- **Cost**: $25/month
- **Use case**: Higher traffic production apps
- **Features**: More resources, better performance

---

## 🌐 Custom Domain (Optional)

Add your own domain:
1. Render Dashboard → Your Service → Settings
2. Scroll to "Custom Domain"
3. Click "Add Custom Domain"
4. Follow DNS configuration instructions
5. Render provides free SSL certificates

---

## 📚 Additional Resources

- **Render Documentation**: https://render.com/docs
- **Docker Best Practices**: https://docs.docker.com/develop/dev-best-practices/
- **Flask Deployment**: https://flask.palletsprojects.com/en/3.0.x/deploying/

---

## ✨ Quick Start Checklist

- [ ] Create Git repository with 3 files
- [ ] Push to GitHub/GitLab
- [ ] Sign up for Render account
- [ ] Create new Web Service
- [ ] Connect repository
- [ ] Select Docker environment
- [ ] Choose instance type (Free or Starter)
- [ ] Click "Create Web Service"
- [ ] Wait for deployment (~2-3 minutes)
- [ ] Test with HAR file upload
- [ ] Verify alerts display correctly

---

## 🎯 Success Criteria

Your deployment is successful when:
- ✅ Application loads at Render URL
- ✅ HAR file upload works
- ✅ Analysis results display
- ✅ Meta/TikTok/LinkedIn alerts appear when detected
- ✅ CSV export functions correctly
- ✅ No errors in Render logs

---

## 🆘 Support

**Render Support:**
- Documentation: https://render.com/docs
- Community: https://community.render.com
- Email: support@render.com

**Application Issues:**
- Check Render logs first
- Verify all files are present in repository
- Test Docker container locally
- Review this deployment guide

---

**Your HAR Privacy Analyzer is now ready for deployment! 🚀**
