# Quick Start Guide
==================

## 🚀 Quick Start (Windows)

### Step 1: Setup Backend
```cmd
cd backend
setup_env.bat
```

### Step 2: Start Backend Server
```cmd
run_server.bat
```
Keep this terminal open!

### Step 3: Setup Frontend (New Terminal)
```cmd
cd frontend
npm install
npm run dev
```

### Step 4: Open Browser
- Frontend: http://localhost:5173
- Backend API Docs: http://localhost:8000/docs

---

## 🐧 Quick Start (Linux/Mac)

### Step 1: Setup Backend
```bash
cd backend
chmod +x setup_env.sh run_server.sh
./setup_env.sh
```

### Step 2: Start Backend Server
```bash
./run_server.sh
```
Keep this terminal open!

### Step 3: Setup Frontend (New Terminal)
```bash
cd frontend
npm install
npm run dev
```

### Step 4: Open Browser
- Frontend: http://localhost:5173
- Backend API Docs: http://localhost:8000/docs

---

## ✅ Verification

1. Backend is running if you see: "🚀 Server starting at http://0.0.0.0:8000"
2. Frontend is running if you see: "Local: http://localhost:5173"
3. Test backend: Visit http://localhost:8000/health (should return {"status": "healthy"})
4. Test frontend: Visit http://localhost:5173 (should show the dashboard)

---

## 🔧 Troubleshooting

**Backend won't start?**
- Make sure Python 3.8+ is installed: `python --version`
- Make sure virtual environment was created: Check for `backend/venv` folder
- Try manual activation: `venv\Scripts\activate` (Windows) or `source venv/bin/activate` (Linux/Mac)

**Frontend can't connect to backend?**
- Make sure backend is running on port 8000
- Check browser console for errors
- Verify CORS settings in `backend/config.yaml`

**Port already in use?**
- Backend: Change port in `run_server.bat`/`run_server.sh` or use `python main.py serve --port 8001`
- Frontend: Change port in `frontend/vite.config.js`

