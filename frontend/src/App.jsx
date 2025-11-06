import React, { useState, useEffect, useRef, createContext, useContext } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { LineChart, Line, AreaChart, Area, PieChart, Pie, Cell, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Activity, Shield, AlertTriangle, CheckCircle, Download, FileText, Code, TrendingUp, Database, Zap } from 'lucide-react';
import * as THREE from 'three';

// Data Context
const DataContext = createContext();

const DataProvider = ({ children }) => {
  const [complianceData, setComplianceData] = useState({
    score: 87.5,
    riskLevel: 'Medium',
    validControls: 142,
    gaps: 23,
    trend: [
      { month: 'Jan', score: 75 },
      { month: 'Feb', score: 78 },
      { month: 'Mar', score: 82 },
      { month: 'Apr', score: 85 },
      { month: 'May', score: 87.5 }
    ],
    categories: [
      { name: 'ISO 27001', value: 92, compliant: 89, total: 97 },
      { name: 'RBI Cyber', value: 85, compliant: 68, total: 80 },
      { name: 'CIS Controls', value: 84, compliant: 151, total: 180 },
      { name: 'NIST', value: 88, compliant: 176, total: 200 }
    ],
    distribution: [
      { name: 'Compliant', value: 65 },
      { name: 'Partial', value: 20 },
      { name: 'Non-Compliant', value: 15 }
    ],
    remediation: [
      { id: 1, severity: 'Critical', title: 'Enable MFA for Admin Accounts', framework: 'ISO 27001 A.9.4.2', script: 'az ad policy update --enable-mfa true' },
      { id: 2, severity: 'High', title: 'Patch OpenSSL Vulnerability', framework: 'CIS 3.4', script: 'sudo apt-get update && sudo apt-get upgrade openssl' },
      { id: 3, severity: 'High', title: 'Configure Firewall Rules', framework: 'RBI 8.2.1', script: 'ufw enable && ufw default deny incoming' },
      { id: 4, severity: 'Medium', title: 'Enable Audit Logging', framework: 'NIST AC-2', script: 'auditctl -e 1 && service auditd restart' },
      { id: 5, severity: 'Medium', title: 'Update Password Policy', framework: 'ISO 27001 A.9.4.3', script: 'pwpolicy -setglobalpolicy "minChars=12"' }
    ]
  });

  const [reports, setReports] = useState([
    { id: 1, name: 'Q2 2024 Compliance Report', date: '2024-05-15', frameworks: ['ISO 27001', 'RBI'], score: 87.5 },
    { id: 2, name: 'Security Audit - May', date: '2024-05-10', frameworks: ['CIS', 'NIST'], score: 85.2 },
    { id: 3, name: 'Monthly Control Assessment', date: '2024-05-01', frameworks: ['ISO 27001'], score: 92.1 }
  ]);

  return (
    <DataContext.Provider value={{ complianceData, setComplianceData, reports, setReports }}>
      {children}
    </DataContext.Provider>
  );
};

const useData = () => useContext(DataContext);

// Three.js Background Component
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

    // Create particle field
    const particlesGeometry = new THREE.BufferGeometry();
    const particlesCount = 3200;
    const posArray = new Float32Array(particlesCount * 3);

    for (let i = 0; i < particlesCount * 3; i++) {
      posArray[i] = (Math.random() - 0.5) * 100;
    }

    particlesGeometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));

    const particlesMaterial = new THREE.PointsMaterial({
      size: 0.12,
      color: 0x00d9ff,
      transparent: true,
      opacity: 0.8,
      blending: THREE.AdditiveBlending
    });

    const particlesMesh = new THREE.Points(particlesGeometry, particlesMaterial);
    scene.add(particlesMesh);

    // Create grid
    const gridHelper = new THREE.GridHelper(100, 50, 0x00d9ff, 0x1a1a2e);
    gridHelper.material.opacity = 0.12;
    gridHelper.material.transparent = true;
    scene.add(gridHelper);

    camera.position.z = 50;
    camera.position.y = 10;

    let animationId;
    let t = 0;
    const animate = () => {
      animationId = requestAnimationFrame(animate);
      
      particlesMesh.rotation.y += 0.0005;
      particlesMesh.rotation.x += 0.0002;
      t += 0.003;
      gridHelper.material.opacity = 0.10 + Math.abs(Math.sin(t)) * 0.06;
      
      const positions = particlesGeometry.attributes.position.array;
      for (let i = 1; i < positions.length; i += 3) {
        positions[i] -= 0.02;
        if (positions[i] < -50) {
          positions[i] = 50;
        }
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

    const handleMouse = (e) => {
      const x = (e.clientX / window.innerWidth) * 2 - 1;
      const y = (e.clientY / window.innerHeight) * 2 - 1;
      camera.position.x += (x * 1.2 - camera.position.x) * 0.02;
      camera.position.y += (-y * 0.8 + 10 - camera.position.y) * 0.02;
      camera.lookAt(scene.position);
    };

    window.addEventListener('resize', handleResize);
    window.addEventListener('mousemove', handleMouse);

    return () => {
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouse);
      cancelAnimationFrame(animationId);
      mountRef.current?.removeChild(renderer.domElement);
    };
  }, []);

  return <div ref={mountRef} className="neon-vignette" style={{ position: 'fixed', top: 0, left: 0, width: '100%', height: '100%', zIndex: -1 }} />;
};

// Animated Gauge Component
const ComplianceGauge = ({ score }) => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = 80;

    const drawGauge = (progress) => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Background arc
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0.75 * Math.PI, 2.25 * Math.PI);
      ctx.strokeStyle = 'rgba(0, 0, 0, 0.1)';
      ctx.lineWidth = 15;
      ctx.stroke();

      // Progress arc
      const gradient = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
      gradient.addColorStop(0, '#00d9ff');
      gradient.addColorStop(0.5, '#7b2ff7');
      gradient.addColorStop(1, '#f107a3');

      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0.75 * Math.PI, 0.75 * Math.PI + (1.5 * Math.PI * progress));
      ctx.strokeStyle = gradient;
      ctx.lineWidth = 15;
      ctx.lineCap = 'round';
      ctx.stroke();

      // Glow effect
      ctx.shadowBlur = 20;
      ctx.shadowColor = '#00d9ff';
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Score text
      ctx.font = 'bold 32px Inter, sans-serif';
      ctx.fillStyle = '#1a1a2e'; // Dark color for visibility
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(`${Math.round(progress * 100)}%`, centerX, centerY);

      ctx.font = '14px Inter, sans-serif';
      ctx.fillStyle = '#4a4a6e'; // Darker gray for visibility
      ctx.fillText('COMPLIANCE', centerX, centerY + 30);
    };

    let currentProgress = 0;
    const targetProgress = score / 100;
    
    const animateGauge = () => {
      if (currentProgress < targetProgress) {
        currentProgress += 0.01;
        drawGauge(currentProgress);
        requestAnimationFrame(animateGauge);
      } else {
        drawGauge(targetProgress);
      }
    };

    animateGauge();
  }, [score]);

  return (
    <canvas 
      ref={canvasRef} 
      width="200" 
      height="200"
      style={{ filter: 'drop-shadow(0 0 20px rgba(0, 217, 255, 0.3))' }}
    />
  );
};

// Glassy Card Component
const GlassCard = ({ children, style, hover = true }) => {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <motion.div
      onHoverStart={() => setIsHovered(true)}
      onHoverEnd={() => setIsHovered(false)}
      animate={{
        scale: hover && isHovered ? 1.02 : 1,
        y: hover && isHovered ? -5 : 0
      }}
      transition={{ type: 'spring', stiffness: 300, damping: 20 }}
      style={{
        background: 'rgba(255, 255, 255, 0.9)',
        backdropFilter: 'blur(10px)',
        border: '1px solid rgba(0, 0, 0, 0.1)',
        borderRadius: '16px',
        padding: '24px',
        position: 'relative',
        overflow: 'hidden',
        boxShadow: isHovered ? '0 8px 32px rgba(0, 217, 255, 0.2)' : '0 4px 16px rgba(0, 0, 0, 0.3)',
        ...style
      }}
    >
      {isHovered && (
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '2px',
          background: 'linear-gradient(90deg, #00d9ff, #7b2ff7, #f107a3)',
          animation: 'shimmer 2s infinite'
        }} />
      )}
      {children}
    </motion.div>
  );
};

// KPI Card
const KPICard = ({ icon: Icon, label, value, trend, color }) => (
  <GlassCard style={{ flex: 1, minWidth: '200px' }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div style={{
          background: `linear-gradient(135deg, ${color}20, ${color}40)`,
          borderRadius: '12px',
          padding: '12px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <Icon size={24} color={color} />
        </div>
        <div>
          <div style={{ fontSize: '12px', color: '#4a4a6e', marginBottom: '4px' }}>
            {label}
          </div>
          <div style={{ fontSize: '28px', fontWeight: 'bold', color: '#1a1a2e' }}>
            {value}
          </div>
        </div>
      </div>
      {trend && (
        <div style={{
          fontSize: '12px',
          color: trend > 0 ? '#00ff88' : '#ff4444',
          display: 'flex',
          alignItems: 'center',
          gap: '4px'
        }}>
          <TrendingUp size={14} style={{ transform: trend < 0 ? 'rotate(180deg)' : 'none' }} />
          {Math.abs(trend)}%
        </div>
      )}
    </div>
  </GlassCard>
);

// Hero Section
const HeroSection = () => {
  const { complianceData } = useData();

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.8 }}
      style={{
        padding: '60px 40px',
        textAlign: 'center',
        marginBottom: '40px'
      }}
    >
      <motion.h1
        style={{
          fontSize: '56px',
          fontWeight: 'bold',
          background: 'linear-gradient(135deg, #00d9ff, #7b2ff7, #f107a3)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          marginBottom: '16px',
          letterSpacing: '-1px'
        }}
        animate={{
          backgroundPosition: ['0%', '100%', '0%']
        }}
        transition={{
          duration: 5,
          repeat: Infinity,
          ease: 'linear'
        }}
      >
        Compliance AI Engine
      </motion.h1>
      <p style={{
        fontSize: '20px',
        color: '#2a2a3e',
        marginBottom: '40px'
      }}>
        Your Compliance. Quantified. Simplified.
      </p>
      
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '40px' }}>
        <ComplianceGauge score={complianceData.score} />
      </div>

      <div style={{
        display: 'flex',
        gap: '20px',
        flexWrap: 'wrap',
        justifyContent: 'center'
      }}>
        <KPICard
          icon={Shield}
          label="COMPLIANCE SCORE"
          value={`${complianceData.score}%`}
          trend={2.5}
          color="#00d9ff"
        />
        <KPICard
          icon={AlertTriangle}
          label="RISK LEVEL"
          value={complianceData.riskLevel}
          color="#f107a3"
        />
        <KPICard
          icon={CheckCircle}
          label="VALID CONTROLS"
          value={complianceData.validControls}
          trend={5}
          color="#00ff88"
        />
        <KPICard
          icon={Activity}
          label="GAPS FOUND"
          value={complianceData.gaps}
          color="#ff9800"
        />
      </div>
    </motion.div>
  );
};

// Compliance Trend Chart
const ComplianceTrendChart = () => {
  const { complianceData } = useData();

  return (
    <GlassCard>
      <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#1a1a2e', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <TrendingUp size={20} color="#00d9ff" />
        Compliance Trend
      </h3>
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={complianceData.trend}>
          <defs>
            <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#00d9ff" stopOpacity={0.8}/>
              <stop offset="95%" stopColor="#7b2ff7" stopOpacity={0.1}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.1)" />
          <XAxis dataKey="month" stroke="rgba(0,0,0,0.6)" />
          <YAxis stroke="rgba(0,0,0,0.6)" domain={[0, 100]} />
          <Tooltip
            contentStyle={{
              background: 'rgba(255, 255, 255, 0.95)',
              border: '1px solid rgba(0, 217, 255, 0.3)',
              borderRadius: '8px',
              color: '#1a1a2e'
            }}
          />
          <Area
            type="monotone"
            dataKey="score"
            stroke="#00d9ff"
            strokeWidth={3}
            fillOpacity={1}
            fill="url(#colorScore)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </GlassCard>
  );
};

// Framework Radar Chart
const FrameworkRadar = () => {
  const { complianceData } = useData();

  return (
    <GlassCard>
      <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#1a1a2e', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Shield size={20} color="#7b2ff7" />
        Framework Coverage
      </h3>
      <ResponsiveContainer width="100%" height={300}>
        <RadarChart data={complianceData.categories}>
          <PolarGrid stroke="rgba(0,0,0,0.2)" />
          <PolarAngleAxis dataKey="name" stroke="rgba(0,0,0,0.6)" />
          <PolarRadiusAxis angle={90} domain={[0, 100]} stroke="rgba(0,0,0,0.4)" />
          <Radar name="Compliance" dataKey="value" stroke="#00d9ff" fill="#00d9ff" fillOpacity={0.6} />
          <Tooltip
            contentStyle={{
              background: 'rgba(255, 255, 255, 0.95)',
              border: '1px solid rgba(0, 217, 255, 0.3)',
              borderRadius: '8px',
              color: '#1a1a2e'
            }}
          />
        </RadarChart>
      </ResponsiveContainer>
    </GlassCard>
  );
};

// Distribution Pie Chart
const DistributionChart = () => {
  const { complianceData } = useData();
  const COLORS = ['#00ff88', '#ff9800', '#ff4444'];

  return (
    <GlassCard>
      <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#1a1a2e', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Database size={20} color="#f107a3" />
        Control Distribution
      </h3>
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={complianceData.distribution}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
            outerRadius={100}
            fill="#8884d8"
            dataKey="value"
          >
            {complianceData.distribution.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: 'rgba(255, 255, 255, 0.95)',
              border: '1px solid rgba(0, 217, 255, 0.3)',
              borderRadius: '8px',
              color: '#1a1a2e'
            }}
          />
        </PieChart>
      </ResponsiveContainer>
    </GlassCard>
  );
};

// Category Heatmap
const CategoryHeatmap = () => {
  const { complianceData } = useData();

  const getColorByScore = (score) => {
    if (score >= 90) return '#00ff88';
    if (score >= 75) return '#00d9ff';
    if (score >= 60) return '#ff9800';
    return '#ff4444';
  };

  return (
    <GlassCard>
      <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#1a1a2e', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Activity size={20} color="#00ff88" />
        Framework Status
      </h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {complianceData.categories.map((cat, idx) => (
          <motion.div
            key={idx}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: idx * 0.1 }}
            style={{
              background: 'rgba(248, 249, 250, 0.8)',
              borderRadius: '12px',
              padding: '16px',
              border: '1px solid rgba(0, 0, 0, 0.1)'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
              <span style={{ color: '#1a1a2e', fontWeight: '600' }}>{cat.name}</span>
              <span style={{ color: getColorByScore(cat.value), fontWeight: 'bold' }}>
                {cat.value}%
              </span>
            </div>
            <div style={{
              width: '100%',
              height: '8px',
              background: 'rgba(255, 255, 255, 0.1)',
              borderRadius: '4px',
              overflow: 'hidden'
            }}>
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${cat.value}%` }}
                transition={{ duration: 1, delay: idx * 0.1 }}
                style={{
                  height: '100%',
                  background: `linear-gradient(90deg, ${getColorByScore(cat.value)}, ${getColorByScore(cat.value)}99)`,
                  boxShadow: `0 0 10px ${getColorByScore(cat.value)}66`
                }}
              />
            </div>
            <div style={{ fontSize: '12px', color: '#4a4a6e', marginTop: '8px' }}>
              {cat.compliant} / {cat.total} controls compliant
            </div>
          </motion.div>
        ))}
      </div>
    </GlassCard>
  );
};

// Remediation Panel
const RemediationPanel = () => {
  const { complianceData } = useData();
  const [selectedSeverity, setSelectedSeverity] = useState('All');

  const severityColors = {
    Critical: '#ff4444',
    High: '#ff9800',
    Medium: '#ffeb3b',
    Low: '#00ff88'
  };

  const filteredRemediation = selectedSeverity === 'All' 
    ? complianceData.remediation 
    : complianceData.remediation.filter(r => r.severity === selectedSeverity);

  return (
    <GlassCard>
      <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#1a1a2e', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Code size={20} color="#ff9800" />
        Remediation Center
      </h3>
      
      <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', flexWrap: 'wrap' }}>
        {['All', 'Critical', 'High', 'Medium', 'Low'].map(severity => (
          <motion.button
            key={severity}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => setSelectedSeverity(severity)}
            style={{
              padding: '8px 16px',
              borderRadius: '8px',
              border: selectedSeverity === severity ? '1px solid #00d9ff' : '1px solid rgba(0, 0, 0, 0.2)',
              background: selectedSeverity === severity ? 'rgba(0, 217, 255, 0.2)' : 'rgba(255, 255, 255, 0.8)',
              color: '#1a1a2e',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '500'
            }}
          >
            {severity}
          </motion.button>
        ))}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', maxHeight: '400px', overflowY: 'auto' }}>
        {filteredRemediation.map((item, idx) => (
          <motion.div
            key={item.id}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.05 }}
            style={{
              background: 'rgba(255, 255, 255, 0.9)',
              borderRadius: '12px',
              padding: '16px',
              border: `1px solid ${severityColors[item.severity]}33`,
              borderLeft: `4px solid ${severityColors[item.severity]}`
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '8px' }}>
              <div>
                <span style={{
                  padding: '4px 8px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: 'bold',
                  background: `${severityColors[item.severity]}22`,
                  color: severityColors[item.severity],
                  marginRight: '8px'
                }}>
                  {item.severity}
                </span>
                <span style={{ color: '#4a4a6e', fontSize: '12px' }}>
                  {item.framework}
                </span>
              </div>
            </div>
            <div style={{ color: '#1a1a2e', fontWeight: '600', marginBottom: '12px' }}>
              {item.title}
            </div>
            <div style={{
              background: 'rgba(255, 255, 255, 0.95)',
              borderRadius: '8px',
              padding: '12px',
              fontFamily: 'monospace',
              fontSize: '13px',
              color: '#00ff88',
              border: '1px solid rgba(0, 255, 136, 0.2)'
            }}>
              <code>{item.script}</code>
            </div>
          </motion.div>
        ))}
      </div>
    </GlassCard>
  );
};

// Reports Section
const ReportsSection = () => {
  const { reports } = useData();

  const handleDownload = (reportId, format) => {
    console.log(`Downloading report ${reportId} as ${format}`);
    // Integrate with backend: axios.get(`/api/reports/${reportId}/download/${format}`)
  };

  return (
    <GlassCard>
      <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#1a1a2e', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <FileText size={20} color="#7b2ff7" />
        Generated Reports
      </h3>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {reports.map((report, idx) => (
          <motion.div
            key={report.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: idx * 0.1 }}
            whileHover={{ scale: 1.02 }}
            style={{
              background: 'rgba(248, 249, 250, 0.8)',
              borderRadius: '12px',
              padding: '20px',
              border: '1px solid rgba(0, 0, 0, 0.1)',
              cursor: 'pointer'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '12px' }}>
              <div>
                <div style={{ color: '#1a1a2e', fontSize: '18px', fontWeight: '600', marginBottom: '8px' }}>
                  {report.name}
                </div>
                <div style={{ fontSize: '13px', color: '#4a4a6e' }}>
                  {report.date} • {report.frameworks.join(', ')}
                </div>
              </div>
              <div style={{
                padding: '8px 16px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, #00d9ff, #7b2ff7)',
                color: '#ffffff',
                fontWeight: 'bold',
                fontSize: '16px'
              }}>
                {report.score}%
              </div>
            </div>
            
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {['pdf', 'excel', 'json'].map(fmt => (
                <motion.button
                  key={fmt}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={() => handleDownload(report.id, fmt)}
                  style={{
                    padding: '8px 12px',
                    borderRadius: '8px',
                    border: '1px solid rgba(0, 0, 0, 0.15)',
                    background: 'rgba(255, 255, 255, 0.8)',
                    color: '#1a1a2e',
                    cursor: 'pointer',
                    fontSize: '12px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.5px'
                  }}
                >
                  {fmt}
                </motion.button>
              ))}
            </div>
          </motion.div>
        ))}
      </div>
    </GlassCard>
  );
};

export default function App() {
  return (
    <DataProvider>
      <ThreeBackground />
      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '24px' }}>
        <HeroSection />
        <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '20px' }}>
          <ComplianceTrendChart />
          <FrameworkRadar />
          <DistributionChart />
          <CategoryHeatmap />
          <RemediationPanel />
          <ReportsSection />
        </div>
      </div>
    </DataProvider>
  );
}