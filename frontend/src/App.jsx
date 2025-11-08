import React, { useState, useEffect, useRef, createContext, useContext } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { LineChart, Line, AreaChart, Area, PieChart, Pie, Cell, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Activity, Shield, AlertTriangle, CheckCircle, Download, FileText, Code, TrendingUp, Database, Zap, Play, RefreshCw, ChevronRight, Loader, Terminal, BarChart3, FileSpreadsheet } from 'lucide-react';
import * as THREE from 'three';
import axios from 'axios';

// Import new components
import RemediationPanel from './components/RemediationPanel';
import VisualizationsPanel from './components/VisualizationsPanel';
import ReactVisualizationsPanel from './components/ReactVisualizationsPanel';
import AdvancedReportsPanel from './components/AdvancedReportsPanel';

// ============================================================================
// API CONFIGURATION
// ============================================================================
// HARDCODED DIRECT CONNECTION - NO PROXY, NO ENV VARS
const API_BASE_URL = 'http://localhost:8000';

console.log('🔧 API Configuration:');
console.log('  - Base URL:', API_BASE_URL);
console.log('  - Environment:', import.meta.env.MODE);
console.log('  - DEV mode:', import.meta.env.DEV);

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 300000, // 5 minutes for long scans
  headers: { 
    'Content-Type': 'application/json',
  },
  withCredentials: false, // Disable credentials for CORS
});

// Add request interceptor to handle errors better
api.interceptors.request.use(
  (config) => {
    const fullUrl = config.baseURL + config.url;
    console.log(`[API] 📤 ${config.method?.toUpperCase()} ${fullUrl}`);
    console.log(`[API]    Base: ${config.baseURL}, Path: ${config.url}`);
    return config;
  },
  (error) => {
    console.error('[API] ❌ Request error:', error);
    return Promise.reject(error);
  }
);

// Add response interceptor for better error handling
api.interceptors.response.use(
  (response) => {
    console.log(`[API] ✅ Response ${response.status} from ${response.config.url}`);
    return response;
  },
  (error) => {
    console.error('[API] ❌ Error details:', {
      code: error.code,
      message: error.message,
      url: error.config?.url,
      baseURL: error.config?.baseURL,
      status: error.response?.status
    });
    
    if (error.code === 'ERR_NETWORK') {
      console.error('[API] 🔴 Network error - Backend connection failed!');
      console.error('[API]    Base URL:', API_BASE_URL);
      console.error('[API]    Full URL:', error.config?.baseURL + error.config?.url);
      console.error('[API]    Is backend running on http://localhost:8000?');
    } else if (error.response) {
      console.error(`[API] 🔴 HTTP ${error.response.status}: ${error.response.statusText}`);
      console.error('[API]    Response data:', error.response.data);
    }
    return Promise.reject(error);
  }
);

// ============================================================================
// DATA CONTEXT
// ============================================================================
const AppContext = createContext();

const AppProvider = ({ children }) => {
  const [scanStatus, setScanStatus] = useState('idle'); // idle, scanning, complete, error
  const [scanProgress, setScanProgress] = useState(0);
  const [complianceData, setComplianceData] = useState(null);
  const [error, setError] = useState(null);

  const pollStatus = async (maxAttempts = 120, interval = 1000) => {
    // Real-time progress tracking with status polling
    let lastProgress = 0;
    for (let i = 0; i < maxAttempts; i++) {
      try {
        const response = await api.get('/api/status');
        const status = response.data;
        
        // Update progress from server in REAL-TIME
        if (status.progress !== undefined && status.progress > lastProgress) {
          lastProgress = status.progress;
          setScanProgress(status.progress);
          console.log(`📊 Progress: ${status.progress}%`);
        }
        
        // Check if collection is done
        if (status.status === 'idle' && status.progress >= 20) {
          return true;
        }
        if (status.status === 'error') {
          setError(status.error || 'Operation failed');
          setScanStatus('error');
          return false;
        }
        
        // Faster polling for real-time updates
        await new Promise(resolve => setTimeout(resolve, interval));
      } catch (err) {
        console.error('Status poll error:', err);
        await new Promise(resolve => setTimeout(resolve, interval));
      }
    }
    return lastProgress >= 20;
  };

  const startScan = async () => {
    try {
      setScanStatus('scanning');
      setScanProgress(0);
      setError(null);

      // Step 1: Start data collection (5%)
      console.log('🚀 Starting compliance scan...');
      setScanProgress(5);
      await api.post('/api/collect');
      
      // Poll for collection completion with REAL-TIME updates
      console.log('📡 Polling for real-time progress...');
      const collectionComplete = await pollStatus(120, 1000); // 2 min with faster polling
      if (!collectionComplete) {
        throw new Error('Data collection timed out');
      }

      // Step 2: Train model (45%)
      console.log('🧠 Training AI model...');
      setScanProgress(45);
      await api.post('/api/train');

      // Step 3: Run comprehensive audit (70%)
      console.log('🔍 Running compliance audit...');
      setScanProgress(70);
      const auditResponse = await api.get('/api/audit/report');

      // Step 4: Generate reports (90%)
      console.log('📄 Generating reports...');
      setScanProgress(90);
      const reportsResponse = await api.get('/api/reports/frontend');

      // Complete (100%)
      console.log('✅ Scan complete!');
      setScanProgress(100);
      setComplianceData(reportsResponse.data);
      setScanStatus('complete');

    } catch (err) {
      console.error('❌ Scan failed:', err);
      setError(err.message || 'Scan failed. Please check backend connection.');
      setScanStatus('error');
      setScanProgress(0);
    }
  };

  const downloadReport = async (format) => {
    try {
      const response = await api.get(`/api/reports/download/${format}`, {
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `compliance_report.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      console.error(`Download ${format} failed:`, err);
    }
  };

  return (
    <AppContext.Provider value={{
      scanStatus,
      scanProgress,
      complianceData,
      error,
      startScan,
      downloadReport
    }}>
      {children}
    </AppContext.Provider>
  );
};

const useApp = () => useContext(AppContext);

// ============================================================================
// THREE.JS BACKGROUND
// ============================================================================
const ThreeBackground = () => {
  const mountRef = useRef(null);

  useEffect(() => {
    if (!mountRef.current) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0);
    mountRef.current.appendChild(renderer.domElement);

    // Particle field
    const particlesGeometry = new THREE.BufferGeometry();
    const particlesCount = 2500;
    const posArray = new Float32Array(particlesCount * 3);

    for (let i = 0; i < particlesCount * 3; i++) {
      posArray[i] = (Math.random() - 0.5) * 120;
    }

    particlesGeometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));

    const particlesMaterial = new THREE.PointsMaterial({
      size: 0.08,
      color: 0xFFD700, // GOLD particles
      transparent: true,
      opacity: 0.6,
      blending: THREE.AdditiveBlending
    });

    const particlesMesh = new THREE.Points(particlesGeometry, particlesMaterial);
    scene.add(particlesMesh);

    // Grid
    const gridHelper = new THREE.GridHelper(100, 40, 0x8B0000, 0x1a0000); // BURGUNDY grid
    gridHelper.material.opacity = 0.08;
    gridHelper.material.transparent = true;
    scene.add(gridHelper);

    camera.position.z = 50;
    camera.position.y = 15;

    let animationId;
    const animate = () => {
      animationId = requestAnimationFrame(animate);
      particlesMesh.rotation.y += 0.0003;
      const positions = particlesGeometry.attributes.position.array;
      for (let i = 1; i < positions.length; i += 3) {
        positions[i] -= 0.015;
        if (positions[i] < -60) positions[i] = 60;
      }
      particlesGeometry.attributes.position.needsUpdate = true;
      renderer.render(scene, camera);
    };

    animate();

    const handleResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationId);
      if (mountRef.current) mountRef.current.removeChild(renderer.domElement);
    };
  }, []);

  return <div ref={mountRef} style={{ position: 'fixed', top: 0, left: 0, width: '100%', height: '100%', zIndex: 0 }} />;
};

// ============================================================================
// LANDING/SCAN PAGE
// ============================================================================
const ScanPage = () => {
  const { scanStatus, scanProgress, startScan, error } = useApp();

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      position: 'relative',
      zIndex: 1,
      padding: '40px'
    }}>
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
        style={{ textAlign: 'center', maxWidth: '800px' }}
      >
        {/* Logo/Title */}
        <motion.div
          animate={{ 
            scale: [1, 1.02, 1],
            filter: ['brightness(1)', 'brightness(1.2)', 'brightness(1)']
          }}
          transition={{ duration: 3, repeat: Infinity }}
        >
          <Shield size={80} color="#FFD700" style={{ marginBottom: '20px', filter: 'drop-shadow(0 0 20px rgba(255,215,0,0.5))' }} />
        </motion.div>

        <h1 style={{
          fontSize: '72px',
          fontWeight: '700',
          background: 'linear-gradient(135deg, #C9A961, #D4AF37, #B8860B)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          marginBottom: '16px',
          letterSpacing: '3px',
          fontFamily: 'Georgia, serif'
        }}>
          AUDITEASE
        </h1>

        <p style={{
          fontSize: '22px',
          color: 'rgba(201, 169, 97, 0.9)',
          marginBottom: '40px',
          fontWeight: '300',
          letterSpacing: '1px',
          fontFamily: 'Georgia, serif'
        }}>
          Enterprise Compliance & Audit Intelligence
        </p>

        {/* Scan Status */}
        {scanStatus === 'idle' && (
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={startScan}
            style={{
              padding: '20px 50px',
              fontSize: '20px',
              fontWeight: '600',
              background: 'linear-gradient(135deg, #C9A961, #B8860B)',
              border: 'none',
              borderRadius: '50px',
              color: '#FFFFFF',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              margin: '0 auto',
              boxShadow: '0 10px 40px rgba(201, 169, 97, 0.4)',
              transition: 'all 0.3s',
              fontFamily: 'Georgia, serif',
              letterSpacing: '1px'
            }}
          >
            <Play size={24} />
            Initialize Compliance Scan
          </motion.button>
        )}

        {scanStatus === 'scanning' && (
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            style={{ 
              marginTop: '50px',
              padding: '40px',
              background: 'rgba(201, 169, 97, 0.05)',
              border: '2px solid rgba(201, 169, 97, 0.2)',
              borderRadius: '16px',
              maxWidth: '600px',
              margin: '50px auto 0'
            }}
          >
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '15px',
              marginBottom: '30px'
            }}>
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
              >
                <Loader size={36} color="#C9A961" />
              </motion.div>
              <span style={{ 
                fontSize: '22px', 
                color: '#C9A961', 
                fontWeight: '600',
                letterSpacing: '1px',
                fontFamily: 'Georgia, serif'
              }}>
                Analyzing Compliance...
              </span>
            </div>

            {/* Elegant Progress Bar */}
            <div style={{
              width: '100%',
              height: '12px',
              background: 'rgba(201, 169, 97, 0.1)',
              borderRadius: '20px',
              overflow: 'hidden',
              margin: '0 auto 20px',
              position: 'relative',
              boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.2)'
            }}>
              <motion.div
                initial={{ width: '0%' }}
                animate={{ width: `${scanProgress}%` }}
                transition={{ duration: 0.3, ease: 'easeInOut' }}
                style={{
                  height: '100%',
                  background: 'linear-gradient(90deg, #C9A961, #D4AF37, #B8860B)',
                  boxShadow: '0 0 20px rgba(201, 169, 97, 0.6)',
                  borderRadius: '20px'
                }}
              />
            </div>

            <p style={{ 
              marginTop: '20px', 
              color: '#C9A961', 
              fontSize: '24px',
              fontWeight: 'bold',
              fontFamily: 'Georgia, serif',
              textAlign: 'center'
            }}>
              {scanProgress}% Complete
            </p>

            <div style={{ 
              marginTop: '25px', 
              fontSize: '16px', 
              color: 'rgba(201, 169, 97, 0.7)',
              fontFamily: 'Georgia, serif',
              textAlign: 'center'
            }}>
              {scanProgress < 30 && '📊 Collecting compliance data from system...'}
              {scanProgress >= 30 && scanProgress < 50 && '🧠 Training AI compliance models...'}
              {scanProgress >= 50 && scanProgress < 80 && '🔍 Running comprehensive security audit...'}
              {scanProgress >= 80 && '📄 Generating executive reports...'}
            </div>
          </motion.div>
        )}

        {scanStatus === 'error' && (
          <div style={{
            marginTop: '40px',
            padding: '20px',
            background: 'rgba(255,68,68,0.1)',
            border: '1px solid rgba(255,68,68,0.3)',
            borderRadius: '12px'
          }}>
            <AlertTriangle size={32} color="#ff4444" style={{ marginBottom: '10px' }} />
            <p style={{ color: '#ff4444', fontSize: '16px' }}>{error}</p>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={startScan}
              style={{
                marginTop: '20px',
                padding: '12px 30px',
                background: 'rgba(0,217,255,0.2)',
                border: '1px solid #FFD700',
                borderRadius: '8px',
                color: '#FFD700',
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: '500'
              }}
            >
              <RefreshCw size={16} style={{ marginRight: '8px', display: 'inline', verticalAlign: 'middle' }} />
              Retry Scan
            </motion.button>
          </div>
        )}
      </motion.div>
    </div>
  );
};

// ============================================================================
// DASHBOARD PAGE
// ============================================================================
const DashboardPage = () => {
  const { complianceData, downloadReport } = useApp();
  const [activeTab, setActiveTab] = useState('overview');

  if (!complianceData) {
    return (
      <div style={{ padding: '100px 40px', textAlign: 'center', color: '#fff' }}>
        <Loader size={48} color="#FFD700" />
        <p style={{ marginTop: '20px' }}>Loading dashboard data...</p>
      </div>
    );
  }

  const { dashboard_summary, key_metrics, framework_scores, category_breakdown, severity_distribution, priority_issues, compliance_trend } = complianceData;

  const tabs = [
    { id: 'overview', name: 'Overview', icon: Activity },
    { id: 'remediation', name: 'Remediation', icon: Terminal },
    { id: 'visualizations', name: 'Visualizations', icon: BarChart3 },
    { id: 'reports', name: 'Reports', icon: FileSpreadsheet }
  ];

  return (
    <div style={{ padding: '100px 40px 40px', position: 'relative', zIndex: 1 }}>
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        style={{ marginBottom: '30px', textAlign: 'center' }}
      >
        <h1 style={{
          fontSize: '42px',
          fontWeight: 'bold',
          background: 'linear-gradient(135deg, #C9A961, #B8860B)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          marginBottom: '12px',
          letterSpacing: '1px'
        }}>
          AuditEase Dashboard
        </h1>
        <p style={{ fontSize: '16px', color: 'rgba(255,255,255,0.7)' }}>
          {dashboard_summary.company.name} • {dashboard_summary.assessment_date.split('T')[0]}
        </p>
      </motion.div>

      {/* Tabs */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          display: 'flex',
          gap: '10px',
          marginBottom: '30px',
          background: 'rgba(255,255,255,0.05)',
          padding: '8px',
          borderRadius: '16px',
          border: '1px solid rgba(255,255,255,0.1)'
        }}
      >
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <motion.button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              style={{
                flex: 1,
                padding: '14px 20px',
                background: isActive ? 'linear-gradient(135deg, #8B0000, #FFD700)' : 'transparent',
                border: 'none',
                borderRadius: '12px',
                color: '#fff',
                fontSize: '15px',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                transition: 'all 0.3s ease'
              }}
            >
              <Icon size={20} />
              {tab.name}
            </motion.button>
          );
        })}
      </motion.div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        {activeTab === 'overview' && (
          <motion.div
            key="overview"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
            transition={{ duration: 0.3 }}
          >
            <DashboardOverviewContent
              dashboard_summary={dashboard_summary}
              key_metrics={key_metrics}
              framework_scores={framework_scores}
              category_breakdown={category_breakdown}
              severity_distribution={severity_distribution}
              priority_issues={priority_issues}
              compliance_trend={compliance_trend}
              downloadReport={downloadReport}
            />
          </motion.div>
        )}

        {activeTab === 'remediation' && (
          <motion.div
            key="remediation"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
            transition={{ duration: 0.3 }}
          >
            <RemediationPanel />
          </motion.div>
        )}

        {activeTab === 'visualizations' && (
          <motion.div
            key="visualizations"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
            transition={{ duration: 0.3 }}
          >
            <ReactVisualizationsPanel complianceData={complianceData} />
          </motion.div>
        )}

        {activeTab === 'reports' && (
          <motion.div
            key="reports"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
            transition={{ duration: 0.3 }}
          >
            <AdvancedReportsPanel />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// Extracted Overview Content Component
const DashboardOverviewContent = ({
  dashboard_summary,
  key_metrics,
  framework_scores,
  category_breakdown,
  severity_distribution,
  priority_issues,
  compliance_trend,
  downloadReport
}) => {
  return (
    <>
      {/* KPI Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '20px',
        marginBottom: '40px'
      }}>
        <KPICard
          icon={Shield}
          label="Overall Score"
          value={`${dashboard_summary.overall_score.toFixed(1)}%`}
          color="#FFD700"
          trend={"+2.5%"}
        />
        <KPICard
          icon={CheckCircle}
          label="Rules Passed"
          value={`${key_metrics.rules_passed}/${key_metrics.total_rules_checked}`}
          color="#00ff88"
        />
        <KPICard
          icon={AlertTriangle}
          label="Critical Issues"
          value={key_metrics.critical_issues}
          color="#ff4444"
        />
        <KPICard
          icon={Activity}
          label="Risk Level"
          value={dashboard_summary.risk_level}
          color={dashboard_summary.risk_level === 'LOW' ? '#00ff88' : '#ff9800'}
        />
      </div>

      {/* Main Grid - 2 Column Layout */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '24px', marginBottom: '24px' }}>
        {/* Compliance Trend */}
        <ChartCard title="Compliance Trend" icon={TrendingUp}>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={compliance_trend}>
              <defs>
                <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#FFD700" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#8B0000" stopOpacity={0.1}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="date" stroke="rgba(255,255,255,0.5)" />
              <YAxis stroke="rgba(255,255,255,0.5)" domain={[0, 100]} />
              <Tooltip contentStyle={{ background: '#0a0a1e', border: '1px solid #FFD700', borderRadius: '8px' }} />
              <Area type="monotone" dataKey="score" stroke="#FFD700" strokeWidth={3} fill="url(#trendGradient)" />
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* Framework Scores Radar */}
        <ChartCard title="Framework Coverage" icon={Shield}>
          <ResponsiveContainer width="100%" height={280}>
            <RadarChart data={framework_scores}>
              <PolarGrid stroke="rgba(255,255,255,0.15)" />
              <PolarAngleAxis dataKey="name" stroke="rgba(255,255,255,0.6)" />
              <PolarRadiusAxis angle={90} domain={[0, 100]} stroke="rgba(255,255,255,0.4)" />
              <Radar name="Score" dataKey="score" stroke="#FFD700" fill="#FFD700" fillOpacity={0.5} />
              <Tooltip contentStyle={{ background: '#0a0a1e', border: '1px solid #FFD700', borderRadius: '8px' }} />
            </RadarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* Second Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '24px', marginBottom: '24px' }}>
        {/* Framework Scores Bar Chart */}
        <ChartCard title="Framework Comparison" icon={BarChart}>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={framework_scores}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="name" stroke="rgba(255,255,255,0.5)" />
              <YAxis stroke="rgba(255,255,255,0.5)" domain={[0, 100]} />
              <Tooltip contentStyle={{ background: '#0a0a1e', border: '1px solid #FFD700', borderRadius: '8px' }} />
              <Bar dataKey="score" fill="url(#barGradient)" radius={[8, 8, 0, 0]} />
              <defs>
                <linearGradient id="barGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#FFD700" />
                  <stop offset="100%" stopColor="#8B0000" />
                </linearGradient>
              </defs>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* Severity Distribution Pie */}
        <ChartCard title="Issue Severity" icon={AlertTriangle}>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={severity_distribution}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ severity, count }) => `${severity}: ${count}`}
                outerRadius={90}
                fill="#8884d8"
                dataKey="count"
              >
                {severity_distribution.map((entry, index) => {
                  const colors = { CRITICAL: '#ff4444', HIGH: '#ff9800', MEDIUM: '#ffeb3b', LOW: '#00ff88' };
                  return <Cell key={`cell-${index}`} fill={colors[entry.severity] || '#ccc'} />;
                })}
              </Pie>
              <Tooltip contentStyle={{ background: '#0a0a1e', border: '1px solid #FFD700', borderRadius: '8px' }} />
            </PieChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* Category Heatmap */}
      <ChartCard title="Category Compliance Breakdown" icon={Database} fullWidth>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: '12px' }}>
          {category_breakdown.slice(0, 12).map((cat, idx) => (
            <motion.div
              key={idx}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: idx * 0.05 }}
              style={{
                padding: '12px',
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px'
              }}
            >
              <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.5)', marginBottom: '6px' }}>
                {cat.framework} • {cat.category}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '18px', fontWeight: 'bold', color: '#fff' }}>
                  {cat.compliance_pct.toFixed(1)}%
                </span>
                <span style={{ fontSize: '12px', color: 'rgba(255,255,255,0.5)' }}>
                  {cat.passed}/{cat.total}
                </span>
              </div>
              <div style={{ width: '100%', height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '2px', overflow: 'hidden' }}>
                <div style={{
                  width: `${cat.compliance_pct}%`,
                  height: '100%',
                  background: cat.compliance_pct >= 80 ? '#00ff88' : cat.compliance_pct >= 60 ? '#ff9800' : '#ff4444'
                }} />
              </div>
            </motion.div>
          ))}
        </div>
      </ChartCard>

      {/* Priority Issues Table */}
      <ChartCard title="Priority Issues" icon={AlertTriangle} fullWidth>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                <th style={tableHeaderStyle}>Priority</th>
                <th style={tableHeaderStyle}>Issue</th>
                <th style={tableHeaderStyle}>Category</th>
                <th style={tableHeaderStyle}>Severity</th>
                <th style={tableHeaderStyle}>Status</th>
              </tr>
            </thead>
            <tbody>
              {priority_issues.slice(0, 8).map((issue, idx) => (
                <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  <td style={tableCellStyle}>
                    <span style={{
                      padding: '4px 8px',
                      borderRadius: '4px',
                      background: issue.severity === 'CRITICAL' ? 'rgba(255,68,68,0.2)' : 'rgba(255,152,0,0.2)',
                      color: issue.severity === 'CRITICAL' ? '#ff4444' : '#ff9800',
                      fontSize: '12px',
                      fontWeight: 'bold'
                    }}>
                      {issue.priority || 'P1'}
                    </span>
                  </td>
                  <td style={tableCellStyle}>{issue.title || 'N/A'}</td>
                  <td style={tableCellStyle}>{issue.category || 'N/A'}</td>
                  <td style={tableCellStyle}>
                    <span style={{
                      padding: '4px 8px',
                      borderRadius: '4px',
                      background: getSeverityColor(issue.severity, 0.2),
                      color: getSeverityColor(issue.severity, 1),
                      fontSize: '11px',
                      fontWeight: 'bold'
                    }}>
                      {issue.severity || 'MEDIUM'}
                    </span>
                  </td>
                  <td style={tableCellStyle}>
                    <span style={{ color: 'rgba(255,255,255,0.5)', fontSize: '12px' }}>
                      {issue.current_status != null ? String(issue.current_status) : 'N/A'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </ChartCard>

      {/* Download Actions */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          marginTop: '40px',
          padding: '30px',
          background: 'rgba(255,255,255,0.03)',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: '16px',
          textAlign: 'center'
        }}
      >
        <h3 style={{ fontSize: '20px', color: '#fff', marginBottom: '20px' }}>Download Reports</h3>
        <div style={{ display: 'flex', gap: '15px', justifyContent: 'center', flexWrap: 'wrap' }}>
          {['pdf', 'excel', 'json'].map(format => (
            <motion.button
              key={format}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => downloadReport(format)}
              style={{
                padding: '14px 28px',
                background: 'linear-gradient(135deg, #8B0000, #FFD700)',
                border: 'none',
                borderRadius: '10px',
                color: '#fff',
                fontSize: '14px',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                textTransform: 'uppercase'
              }}
            >
              <Download size={18} />
              {format.toUpperCase()}
            </motion.button>
          ))}
        </div>
      </motion.div>
    </>
  );
};

// ============================================================================
// REUSABLE COMPONENTS
// ============================================================================
const KPICard = ({ icon: Icon, label, value, color, trend }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    whileHover={{ y: -5, boxShadow: `0 10px 30px ${color}40` }}
    style={{
      padding: '24px',
      background: 'rgba(255,255,255,0.05)',
      backdropFilter: 'blur(10px)',
      border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: '16px',
      position: 'relative',
      overflow: 'hidden'
    }}
  >
    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
      <div style={{
        padding: '10px',
        background: `${color}20`,
        borderRadius: '10px'
      }}>
        <Icon size={24} color={color} />
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.5)', marginBottom: '4px' }}>
          {label}
        </div>
        <div style={{ fontSize: '28px', fontWeight: 'bold', color: '#fff' }}>
          {value}
        </div>
      </div>
    </div>
    {trend && (
      <div style={{ fontSize: '12px', color: '#00ff88', display: 'flex', alignItems: 'center', gap: '4px' }}>
        <TrendingUp size={14} />
        {trend}
      </div>
    )}
  </motion.div>
);

const ChartCard = ({ title, icon: Icon, children, fullWidth }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    style={{
      padding: '24px',
      background: 'rgba(255,255,255,0.05)',
      backdropFilter: 'blur(10px)',
      border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: '16px',
      gridColumn: fullWidth ? '1 / -1' : 'auto'
    }}
  >
    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
      <Icon size={20} color="#FFD700" />
      <h3 style={{ fontSize: '18px', fontWeight: '600', color: '#fff' }}>{title}</h3>
    </div>
    {children}
  </motion.div>
);

// Table Styles
const tableHeaderStyle = {
  padding: '12px',
  textAlign: 'left',
  fontSize: '12px',
  fontWeight: '600',
  color: 'rgba(255,255,255,0.6)',
  textTransform: 'uppercase',
  letterSpacing: '0.5px'
};

const tableCellStyle = {
  padding: '12px',
  fontSize: '14px',
  color: 'rgba(255,255,255,0.8)'
};

const getSeverityColor = (severity, opacity) => {
  const colors = {
    CRITICAL: '#ff4444',
    HIGH: '#ff9800',
    MEDIUM: '#ffeb3b',
    LOW: '#00ff88'
  };
  const color = colors[severity] || '#ccc';
  return opacity < 1 ? color.replace(')', `, ${opacity})`) : color;
};

// ============================================================================
// MAIN APP COMPONENT
// ============================================================================
export default function App() {
  const [appState, setAppState] = useState('landing'); // landing, dashboard

  useEffect(() => {
    // Global styles
    const style = document.createElement('style');
    style.textContent = `
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }
      
      body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        background: #0a0a1e;
        color: #ffffff;
        overflow-x: hidden;
      }
      
      ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
      }
      
      ::-webkit-scrollbar-track {
        background: rgba(0, 0, 0, 0.2);
      }
      
      ::-webkit-scrollbar-thumb {
        background: rgba(0, 217, 255, 0.4);
        border-radius: 4px;
      }
      
      ::-webkit-scrollbar-thumb:hover {
        background: rgba(0, 217, 255, 0.6);
      }
    `;
    document.head.appendChild(style);

    return () => {
      document.head.removeChild(style);
    };
  }, []);

  return (
    <AppProvider>
      <AppContent appState={appState} setAppState={setAppState} />
    </AppProvider>
  );
}

const AppContent = ({ appState, setAppState }) => {
  const { scanStatus } = useApp();

  // Auto-navigate to dashboard when scan completes
  useEffect(() => {
    if (scanStatus === 'complete') {
      setTimeout(() => setAppState('dashboard'), 1000);
    }
  }, [scanStatus, setAppState]);

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #1a0000 0%, #2d0000 50%, #1f0000 100%)',
      position: 'relative'
    }}>
      <ThreeBackground />
      
      {/* Navigation Header */}
      {appState === 'dashboard' && (
        <motion.div
          initial={{ y: -100 }}
          animate={{ y: 0 }}
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            zIndex: 1000,
            background: 'rgba(10, 10, 30, 0.9)',
            backdropFilter: 'blur(10px)',
            borderBottom: '1px solid rgba(255,255,255,0.1)',
            padding: '15px 40px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Shield size={28} color="#C9A961" />
            <span style={{ fontSize: '20px', fontWeight: 'bold', color: '#C9A961', letterSpacing: '2px' }}>AUDITEASE</span>
          </div>
          
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => setAppState('landing')}
            style={{
              padding: '10px 20px',
              background: 'rgba(0,217,255,0.1)',
              border: '1px solid rgba(0,217,255,0.3)',
              borderRadius: '8px',
              color: '#FFD700',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '500',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}
          >
            <RefreshCw size={16} />
            New Scan
          </motion.button>
        </motion.div>
      )}

      {/* Main Content */}
      <AnimatePresence mode="wait">
        {appState === 'landing' && (
          <motion.div
            key="landing"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <ScanPage />
          </motion.div>
        )}
        
        {appState === 'dashboard' && (
          <motion.div
            key="dashboard"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <DashboardPage />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};