# AuditEase - Setup and Run Instructions
==========================================

## Overview
This project consists of a Python FastAPI backend and a React frontend. Follow these instructions to connect and run both components.

## Prerequisites
- Python 3.8 or higher
- Node.js 16+ and npm
- Git (optional)

---

## Backend Setup (Python)

### Windows:
1. Open Command Prompt or PowerShell in the `backend` folder
2. Run the setup script:
   ```
   setup_env.bat
   ```
3. Start the API server:
   ```
   run_server.bat
   ```
   Or manually:
   ```
   venv\Scripts\activate.bat
   python main.py serve --port 8000
   ```

### Linux/Mac:
1. Open Terminal in the `backend` folder
2. Make scripts executable:
   ```bash
   chmod +x setup_env.sh run_server.sh
   ```
3. Run the setup script:
   ```bash
   ./setup_env.sh
   ```
4. Start the API server:
   ```bash
   ./run_server.sh
   ```
   Or manually:
   ```bash
   source venv/bin/activate
   python main.py serve --port 8000
   ```

### Manual Setup (Alternative):
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate.bat
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start server
python main.py serve --port 8000
```

The backend API will be available at:
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Health Check: http://localhost:8000/health

---

## Frontend Setup (React)

1. Open Terminal in the `frontend` folder
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the development server:
   ```bash
   npm run dev
   ```

The frontend will be available at:
- Frontend: http://localhost:5173

---

## Running Both Services

### Terminal 1 - Backend:
```bash
cd backend
# Windows:
run_server.bat
# Linux/Mac:
./run_server.sh
```

### Terminal 2 - Frontend:
```bash
cd frontend
npm run dev
```

---

## API Endpoints

The backend provides the following endpoints:

### Compliance
- `GET /api/compliance/summary` - Get compliance summary
- `GET /api/compliance/report` - Get full compliance report
- `GET /api/compliance/remediation` - Get remediation recommendations
- `POST /api/compliance/train` - Train ML model
- `POST /api/compliance/collect` - Collect compliance data
- `POST /api/compliance/infer` - Run ML inference

### Audit
- `GET /api/audit/report` - Get audit report
- `GET /api/audit/remediation` - Get audit remediation

### Reports
- `POST /api/reports/generate` - Generate reports
- `GET /api/reports/{id}/download/pdf` - Download PDF report
- `GET /api/reports/{id}/download/excel` - Download Excel report
- `GET /api/reports/{id}/remediation` - Download remediation script

---

## Troubleshooting

### Backend Issues:
- **Port already in use**: Change the port in `run_server.bat`/`run_server.sh` or use `python main.py serve --port 8001`
- **Module not found**: Make sure virtual environment is activated and requirements are installed
- **CORS errors**: Check `config.yaml` in backend for CORS origins configuration

### Frontend Issues:
- **Cannot connect to backend**: Ensure backend is running on port 8000
- **API errors**: Check browser console and backend logs
- **Port conflicts**: Change port in `vite.config.js`

### Environment Variables:
- Frontend uses `.env` file for API URL configuration
- Backend uses `config.yaml` for configuration

---

## Project Structure

```
AuditEase/
├── backend/
│   ├── api/              # FastAPI server
│   ├── core/              # Core modules
│   ├── services/          # Business logic services
│   ├── config.yaml        # Configuration
│   ├── requirements.txt   # Python dependencies
│   ├── setup_env.bat      # Windows setup script
│   ├── setup_env.sh       # Linux/Mac setup script
│   ├── run_server.bat     # Windows run script
│   └── run_server.sh      # Linux/Mac run script
│
└── frontend/
    ├── src/
    │   ├── api/           # API client
    │   └── ...
    ├── package.json       # Node dependencies
    └── vite.config.js     # Vite configuration
```

---

## Notes

- The backend uses a virtual environment to isolate Python dependencies
- The frontend uses Vite as the build tool
- CORS is configured to allow frontend-backend communication
- API documentation is available at `/docs` when backend is running

