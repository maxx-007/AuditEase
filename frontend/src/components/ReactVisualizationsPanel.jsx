import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  BarChart, Bar, PieChart, Pie, Cell, LineChart, Line,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';
import { 
  BarChart3, 
  Download, 
  Loader, 
  AlertTriangle,
  TrendingUp,
  Shield,
  Activity
} from 'lucide-react';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const ReactVisualizationsPanel = ({ complianceData }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeChart, setActiveChart] = useState('overview');

  // Extract data from compliance data
  const frameworkScores = complianceData?.framework_scores || [];
  const categoryBreakdown = complianceData?.category_breakdown || [];
  const severityDistribution = complianceData?.severity_distribution || [];
  const complianceTrend = complianceData?.compliance_trend || [];
  const priorityIssues = complianceData?.priority_issues || [];

  const chartTypes = [
    { id: 'overview', name: 'Compliance Overview', icon: Activity },
    { id: 'frameworks', name: 'Framework Comparison', icon: Shield },
    { id: 'categories', name: 'Category Analysis', icon: BarChart3 },
    { id: 'severity', name: 'Severity Distribution', icon: AlertTriangle },
    { id: 'trends', name: 'Compliance Trends', icon: TrendingUp }
  ];

  const COLORS = {
    gold: '#C9A961',
    darkGold: '#B8860B',
    lightGold: '#D4AF37',
    critical: '#8B0000',
    high: '#FF4444',
    medium: '#FFA500',
    low: '#00CC00',
    excellent: '#00FF88'
  };

  const severityColors = {
    CRITICAL: COLORS.critical,
    HIGH: COLORS.high,
    MEDIUM: COLORS.medium,
    LOW: COLORS.low
  };

  const downloadChart = (chartId) => {
    // Implementation for downloading chart as image
    alert('Download functionality coming soon!');
  };

  if (!complianceData) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 mx-auto mb-4" style={{ color: COLORS.gold }} />
          <p style={{ color: COLORS.gold, fontSize: '18px', fontFamily: 'Georgia, serif' }}>
            No compliance data available. Please run a scan first.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          background: `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})`,
          borderRadius: '16px',
          padding: '32px',
          color: '#FFFFFF'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h2 style={{ 
              fontSize: '28px', 
              fontWeight: 'bold', 
              marginBottom: '8px',
              fontFamily: 'Georgia, serif',
              letterSpacing: '1px'
            }}>
              Interactive Analytics
            </h2>
            <p style={{ 
              fontSize: '16px', 
              opacity: 0.9,
              fontFamily: 'Georgia, serif'
            }}>
              Real-time compliance visualizations from your audit data
            </p>
          </div>
          <BarChart3 size={48} style={{ opacity: 0.5 }} />
        </div>
      </motion.div>

      {/* Chart Type Selector */}
      <div style={{
        display: 'flex',
        gap: '12px',
        flexWrap: 'wrap',
        padding: '20px',
        background: 'rgba(201, 169, 97, 0.05)',
        borderRadius: '12px',
        border: '2px solid rgba(201, 169, 97, 0.2)'
      }}>
        {chartTypes.map((chart) => {
          const Icon = chart.icon;
          const isActive = activeChart === chart.id;
          return (
            <motion.button
              key={chart.id}
              onClick={() => setActiveChart(chart.id)}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              style={{
                padding: '12px 24px',
                background: isActive ? `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})` : 'rgba(201, 169, 97, 0.1)',
                border: `2px solid ${isActive ? COLORS.gold : 'rgba(201, 169, 97, 0.3)'}`,
                borderRadius: '8px',
                color: isActive ? '#FFFFFF' : COLORS.gold,
                fontSize: '14px',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontFamily: 'Georgia, serif',
                transition: 'all 0.3s ease'
              }}
            >
              <Icon size={18} />
              {chart.name}
            </motion.button>
          );
        })}
      </div>

      {/* Charts Container */}
      <motion.div
        key={activeChart}
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.3 }}
        style={{
          background: '#FFFFFF',
          borderRadius: '16px',
          padding: '32px',
          boxShadow: '0 4px 20px rgba(201, 169, 97, 0.1)',
          border: '2px solid rgba(201, 169, 97, 0.2)'
        }}
      >
        {/* Compliance Overview */}
        {activeChart === 'overview' && (
          <div>
            <h3 style={{ 
              fontSize: '22px', 
              fontWeight: 'bold', 
              marginBottom: '24px',
              color: COLORS.darkGold,
              fontFamily: 'Georgia, serif'
            }}>
              Compliance Overview
            </h3>
            <ResponsiveContainer width="100%" height={400}>
              <RadarChart data={frameworkScores}>
                <PolarGrid stroke={COLORS.gold} opacity={0.3} />
                <PolarAngleAxis 
                  dataKey="name" 
                  tick={{ fill: COLORS.darkGold, fontFamily: 'Georgia, serif' }}
                />
                <PolarRadiusAxis 
                  angle={90} 
                  domain={[0, 100]} 
                  tick={{ fill: COLORS.gold }}
                />
                <Radar 
                  name="Compliance Score" 
                  dataKey="score" 
                  stroke={COLORS.gold} 
                  fill={COLORS.gold} 
                  fillOpacity={0.6} 
                />
                <Tooltip 
                  contentStyle={{ 
                    background: '#FFFFFF', 
                    border: `2px solid ${COLORS.gold}`,
                    borderRadius: '8px',
                    fontFamily: 'Georgia, serif'
                  }} 
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Framework Comparison */}
        {activeChart === 'frameworks' && (
          <div>
            <h3 style={{ 
              fontSize: '22px', 
              fontWeight: 'bold', 
              marginBottom: '24px',
              color: COLORS.darkGold,
              fontFamily: 'Georgia, serif'
            }}>
              Framework Comparison
            </h3>
            <ResponsiveContainer width="100%" height={400}>
              <BarChart data={frameworkScores}>
                <CartesianGrid strokeDasharray="3 3" stroke={COLORS.gold} opacity={0.3} />
                <XAxis 
                  dataKey="name" 
                  tick={{ fill: COLORS.darkGold, fontFamily: 'Georgia, serif' }}
                />
                <YAxis 
                  domain={[0, 100]} 
                  tick={{ fill: COLORS.gold }}
                />
                <Tooltip 
                  contentStyle={{ 
                    background: '#FFFFFF', 
                    border: `2px solid ${COLORS.gold}`,
                    borderRadius: '8px',
                    fontFamily: 'Georgia, serif'
                  }} 
                />
                <Bar dataKey="score" fill={COLORS.gold} radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Category Analysis */}
        {activeChart === 'categories' && (
          <div>
            <h3 style={{ 
              fontSize: '22px', 
              fontWeight: 'bold', 
              marginBottom: '24px',
              color: COLORS.darkGold,
              fontFamily: 'Georgia, serif'
            }}>
              Category Compliance Analysis
            </h3>
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', 
              gap: '16px',
              marginBottom: '24px'
            }}>
              {categoryBreakdown.slice(0, 12).map((cat, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: idx * 0.05 }}
                  style={{
                    padding: '16px',
                    background: 'rgba(201, 169, 97, 0.05)',
                    border: '2px solid rgba(201, 169, 97, 0.2)',
                    borderRadius: '12px'
                  }}
                >
                  <div style={{ 
                    fontSize: '12px', 
                    color: COLORS.darkGold, 
                    marginBottom: '8px',
                    fontFamily: 'Georgia, serif',
                    fontWeight: '600'
                  }}>
                    {cat.framework} • {cat.category}
                  </div>
                  <div style={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center', 
                    marginBottom: '12px' 
                  }}>
                    <span style={{ 
                      fontSize: '24px', 
                      fontWeight: 'bold', 
                      color: COLORS.gold,
                      fontFamily: 'Georgia, serif'
                    }}>
                      {cat.compliance_pct?.toFixed(1)}%
                    </span>
                    <span style={{ fontSize: '12px', color: COLORS.darkGold }}>
                      {cat.passed}/{cat.total}
                    </span>
                  </div>
                  <div style={{ 
                    width: '100%', 
                    height: '6px', 
                    background: 'rgba(201, 169, 97, 0.2)', 
                    borderRadius: '3px', 
                    overflow: 'hidden' 
                  }}>
                    <div style={{
                      width: `${cat.compliance_pct}%`,
                      height: '100%',
                      background: cat.compliance_pct >= 80 
                        ? COLORS.excellent 
                        : cat.compliance_pct >= 60 
                        ? COLORS.medium 
                        : COLORS.high,
                      borderRadius: '3px',
                      transition: 'width 0.5s ease'
                    }} />
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        )}

        {/* Severity Distribution */}
        {activeChart === 'severity' && (
          <div>
            <h3 style={{ 
              fontSize: '22px', 
              fontWeight: 'bold', 
              marginBottom: '24px',
              color: COLORS.darkGold,
              fontFamily: 'Georgia, serif'
            }}>
              Severity Distribution
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '32px' }}>
              <ResponsiveContainer width="100%" height={350}>
                <PieChart>
                  <Pie
                    data={severityDistribution}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ severity, count }) => `${severity}: ${count}`}
                    outerRadius={120}
                    fill="#8884d8"
                    dataKey="count"
                  >
                    {severityDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={severityColors[entry.severity] || COLORS.gold} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ 
                      background: '#FFFFFF', 
                      border: `2px solid ${COLORS.gold}`,
                      borderRadius: '8px',
                      fontFamily: 'Georgia, serif'
                    }} 
                  />
                </PieChart>
              </ResponsiveContainer>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', justifyContent: 'center' }}>
                {severityDistribution.map((item, idx) => (
                  <div 
                    key={idx}
                    style={{
                      padding: '16px',
                      background: 'rgba(201, 169, 97, 0.05)',
                      border: '2px solid rgba(201, 169, 97, 0.2)',
                      borderRadius: '8px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <div style={{
                        width: '16px',
                        height: '16px',
                        borderRadius: '4px',
                        background: severityColors[item.severity] || COLORS.gold
                      }} />
                      <span style={{ 
                        fontWeight: '600', 
                        color: COLORS.darkGold,
                        fontFamily: 'Georgia, serif'
                      }}>
                        {item.severity}
                      </span>
                    </div>
                    <span style={{ 
                      fontSize: '20px', 
                      fontWeight: 'bold', 
                      color: COLORS.gold,
                      fontFamily: 'Georgia, serif'
                    }}>
                      {item.count}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Compliance Trends */}
        {activeChart === 'trends' && (
          <div>
            <h3 style={{ 
              fontSize: '22px', 
              fontWeight: 'bold', 
              marginBottom: '24px',
              color: COLORS.darkGold,
              fontFamily: 'Georgia, serif'
            }}>
              Compliance Trends Over Time
            </h3>
            <ResponsiveContainer width="100%" height={400}>
              <LineChart data={complianceTrend}>
                <CartesianGrid strokeDasharray="3 3" stroke={COLORS.gold} opacity={0.3} />
                <XAxis 
                  dataKey="date" 
                  tick={{ fill: COLORS.darkGold, fontFamily: 'Georgia, serif' }}
                />
                <YAxis 
                  domain={[0, 100]} 
                  tick={{ fill: COLORS.gold }}
                />
                <Tooltip 
                  contentStyle={{ 
                    background: '#FFFFFF', 
                    border: `2px solid ${COLORS.gold}`,
                    borderRadius: '8px',
                    fontFamily: 'Georgia, serif'
                  }} 
                />
                <Line 
                  type="monotone" 
                  dataKey="score" 
                  stroke={COLORS.gold} 
                  strokeWidth={3}
                  dot={{ fill: COLORS.darkGold, r: 6 }}
                  activeDot={{ r: 8 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </motion.div>

      {/* Export Options */}
      <div style={{
        padding: '24px',
        background: 'rgba(201, 169, 97, 0.05)',
        border: '2px solid rgba(201, 169, 97, 0.2)',
        borderRadius: '12px',
        textAlign: 'center'
      }}>
        <h4 style={{ 
          fontSize: '18px', 
          fontWeight: 'bold', 
          color: COLORS.darkGold,
          marginBottom: '16px',
          fontFamily: 'Georgia, serif'
        }}>
          Export Analytics
        </h4>
        <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
          <button
            onClick={() => downloadChart('png')}
            style={{
              padding: '12px 24px',
              background: `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})`,
              border: 'none',
              borderRadius: '8px',
              color: '#FFFFFF',
              fontSize: '14px',
              fontWeight: '600',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontFamily: 'Georgia, serif'
            }}
          >
            <Download size={18} />
            Download PNG
          </button>
          <button
            onClick={() => downloadChart('pdf')}
            style={{
              padding: '12px 24px',
              background: 'transparent',
              border: `2px solid ${COLORS.gold}`,
              borderRadius: '8px',
              color: COLORS.gold,
              fontSize: '14px',
              fontWeight: '600',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontFamily: 'Georgia, serif'
            }}
          >
            <Download size={18} />
            Download PDF
          </button>
        </div>
      </div>
    </div>
  );
};

export default ReactVisualizationsPanel;

