# HAR Privacy Analyzer - Phase 1 (With Auto-Repair)

## 🎯 **All-in-One Solution**

Upload ANY HAR file - corrupted or not - and get analysis automatically!

**New Features:**
- ✅ **Automatic corruption repair** - no manual steps needed
- ✅ **Seamless user experience** - just upload and analyze
- ✅ **Visual repair notifications** - shows what was fixed
- ✅ **Single application** - no separate tools required

---

## 📁 **Files Included**

```
har-analyzer-phase1/
├── app.py           # Main entry point - RUN THIS
├── backend.py       # Flask backend with auto-repair
└── static/
    └── index.html   # Frontend with repair notifications
```

---

## 🚀 **Quick Start**

### 1. Install Dependencies

```bash
pip install Flask==3.0.0 --break-system-packages
```

### 2. Set Up File Structure

```bash
# Create project folder
mkdir har-analyzer-phase1
cd har-analyzer-phase1

# Copy files:
# - app.py (root folder)
# - backend.py (root folder)
# - index.html (create static/ folder and place here)

mkdir static
mv index.html static/
```

### 3. Run the Application

```bash
python app.py
```

Open: **http://localhost:5000**

---

## 💡 **How It Works**

### **Smart Upload Process:**

1. **User uploads HAR file** (any file, corrupted or clean)
   
2. **Backend tries standard parsing first**
   - If successful → analyze immediately
   - If fails → automatically switch to resilient parser

3. **Resilient parser (if needed):**
   - Extracts entries one-by-one
   - Skips corrupted sections
   - Continues parsing through errors
   - Builds valid HAR structure from extracted data

4. **Analysis runs** on whatever data was successfully loaded

5. **Results displayed** with repair notification if applicable

### **User Experience:**

**For Clean Files:**
```
Upload → Analyze → See Results
(User never knows repair capability exists)
```

**For Corrupted Files:**
```
Upload → Auto-Repair → Analyze → See Results
(User sees notification but doesn't need to do anything)
```

---

## 🎨 **What You'll See**

### **Clean HAR File (No Repair Needed):**

```
┌─────────────────────────────────────────┐
│ Analysis of: example.com                │
│ Session: May 6, 2026 at 10:00 AM       │
│                                          │
│ ✓ No LeadID tracking detected           │
│                                          │
│ 150 Total Requests                      │
│ 45 POST Requests                        │
└─────────────────────────────────────────┘
```

### **Corrupted HAR File (Auto-Repaired):**

```
┌─────────────────────────────────────────┐
│ 🔧 File Automatically Repaired          │
│                                          │
│ Your HAR file had some corrupted        │
│ sections that were automatically        │
│ repaired.                                │
│                                          │
│ 402 entries successfully extracted      │
│ 21 corrupted entries skipped            │
│ 95.0% success rate                      │
│                                          │
│ Analysis is based on repaired data.     │
│ Some information may be missing.        │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ Analysis of: americor.com               │
│ Session: April 28, 2026 at 6:51 PM     │
│                                          │
│ 🚨 LeadID Detected                      │
│                                          │
│ 8 LeadID Requests                       │
│ [PII count]                             │
│ 402 Total Requests                      │
└─────────────────────────────────────────┘
```

---

## 🔧 **Technical Details**

### **Backend Auto-Repair Logic:**

```python
try:
    # Try standard JSON parsing
    har_data = json.loads(har_text)
except json.JSONDecodeError:
    # Standard failed - use resilient parser
    entries, stats = resilient_parse_har(har_text)
    
    # Build valid HAR from extracted entries
    har_data = {
        'log': {
            'entries': entries
        }
    }
    
    # Flag that repair was used
    results['repair_used'] = True
    results['repair_stats'] = stats
```

### **Resilient Parser Strategy:**

1. **Find entries array** boundary in HAR file
2. **Parse entry-by-entry** (not whole file)
3. **Track brace matching** to find complete entries
4. **Skip invalid entries** when JSON parsing fails
5. **Resume from next valid entry** after errors
6. **Return all extracted entries** + statistics

### **What Gets Repaired:**

✅ **UTF-8 encoding errors** - Non-UTF-8 bytes replaced
✅ **Control characters** - Invalid characters stripped
✅ **Malformed JSON** - Entries parsed individually
✅ **Partial corruption** - Bad sections skipped
✅ **Truncated files** - Extracts whatever is readable

### **What Cannot Be Repaired:**

❌ **Completely invalid HAR structure** (no entries array)
❌ **Binary files** (not text-based HAR)
❌ **Empty files**
❌ **100% corrupted** (every entry invalid)

---

## 📊 **Example: Americor HAR Results**

**File:** `matthew_vargas_americor_042826.har` (30MB, corrupted)

**Auto-Repair Results:**
- ✅ Extracted: 402 entries (95% success)
- ⚠️ Skipped: 21 corrupted entries
- 🎯 Found: 8 TrustedForm/LeadID requests

**Analysis Output:**
```
Website: americor.com
Session: 2026-04-28 18:51:42 to 18:52:28 (46 seconds)

LeadID Tracking Detected:
- api.trustedform.com/trustedform.js
- cdn.trustedform.com/bootstrap.js
- api.trustedform.com/certs
- api.trustedform.com/certs/[ID]/snapshot

POST Requests: 57
Total Requests: 402
```

---

## 🎯 **Use Cases**

### **✅ Works For:**

1. **Clean HAR files** - Standard analysis
2. **Minor corruption** - Auto-repair handles it
3. **Major corruption** - Extracts maximum data
4. **Encoding issues** - UTF-8 replacement
5. **Large files** - Up to 100MB supported
6. **Old exports** - Files from different browsers

### **❌ Limitations:**

- Cannot recover deleted data
- Cannot repair 100% corrupted files
- Skipped entries may contain critical data
- Some PII might be in corrupted sections

---

## 🚨 **Important Notes**

### **About Repaired Files:**

When you see the repair notification:
- ✅ Analysis IS valid for the data that was extracted
- ⚠️ Some information MAY be missing from corrupted sections
- 📊 Success rate shows what percentage was recovered
- 💡 Consider re-exporting for 100% completeness

### **Re-Export Recommended If:**

- Success rate < 80%
- LeadID found but no PII shown
- Critical timestamps missing
- Need litigation-grade evidence

### **Repair Is Fine If:**

- Success rate > 90%
- All key data visible
- Timeline complete
- Just need quick analysis

---

## 🎓 **Comparison: Before vs After**

| Feature | Before (Separate Tools) | After (Integrated) |
|---------|------------------------|-------------------|
| **Upload Steps** | 2 (repair + upload) | 1 (just upload) |
| **User Action** | Manual repair needed | Automatic |
| **Tools Required** | Web app + CLI script | Web app only |
| **File Management** | Save cleaned file | Handled internally |
| **User Experience** | Technical, complex | Simple, seamless |
| **Error Messages** | Generic JSON errors | Helpful repair stats |

---

## 📋 **Testing Checklist**

### **Test 1: Clean HAR File**
- [ ] Upload a small, valid HAR
- [ ] No repair notification shown
- [ ] Analysis completes normally
- [ ] Results display correctly

### **Test 2: Corrupted HAR File**  
- [ ] Upload `matthew_vargas_americor_042826.har`
- [ ] Repair notification appears
- [ ] Shows extraction statistics
- [ ] Analysis shows LeadID detection
- [ ] Timeline displays (if PII found)

### **Test 3: Large File**
- [ ] Upload 25-50MB HAR
- [ ] Loading indicator shows
- [ ] Analysis completes
- [ ] No timeout errors

### **Test 4: Multiple Uploads**
- [ ] Analyze first file
- [ ] Click "Analyze Another File"
- [ ] Upload second file
- [ ] Both analyses work correctly

---

## 🐛 **Troubleshooting**

### **"Error analyzing file"**
- File may be 100% corrupted
- Try re-exporting from browser
- Check file is actually .har extension

### **"No LeadID detected" (but expected)**
- LeadID data may be in corrupted sections
- Check repair stats - low success rate?
- Try re-exporting for complete data

### **Loading forever**
- File may be too large (>100MB)
- Refresh page and try smaller file
- Check browser console (F12) for errors

### **Server won't start**
- Port 5000 may be in use
- Try: `lsof -i :5000` to check
- Kill process or change port in app.py

---

## 💾 **File Structure**

### **Correct Setup:**
```
har-analyzer-phase1/
├── app.py              # Entry point
├── backend.py          # Flask + resilient parser
└── static/
    └── index.html      # Frontend
```

### **Common Mistakes:**
❌ `index.html` in root folder (should be in `static/`)
❌ Missing `static/` directory
❌ Wrong file names (must be exact)

---

## 🎉 **Success Indicators**

You'll know it's working when:

✅ Server starts without errors
✅ Can access http://localhost:5000
✅ Clean files analyze normally (no repair notification)
✅ Corrupted files auto-repair (shows repair notification)
✅ Americor HAR shows 8 LeadID requests
✅ Can upload multiple files in sequence

---

## 🚀 **Next Steps**

**Phase 1 Complete!**
- ✅ LeadID detection
- ✅ Large file support
- ✅ Auto-repair for corruption
- ✅ User-friendly interface

**Phase 2 Coming:**
- Google/Facebook/Invoca detection
- Consent mechanism checking
- Pre/post boundary analysis
- Damages calculator
- Vendor comparison matrix

---

## 📞 **Support**

For issues:
1. Check this README troubleshooting section
2. Verify file structure matches above
3. Test with a known-good HAR first
4. Check terminal for error messages
5. Review browser console (F12)

---

**One tool. One upload. Automatic repair. Simple analysis.** 🎯
