import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileSpreadsheet,
  FileText,
  Download,
  Loader,
  CheckCircle,
  AlertTriangle,
  FileJson,
  Table,
  BarChart3,
  Award,
  TrendingUp,
  Shield,
  Sparkles
} from 'lucide-react';
import axios from 'axios';

const API_BASE_URL = '/api';

// Luxury color scheme matching RemediationPanel
const COLORS = {
  gold: '#C9A961',
  darkGold: '#B8860B',
  lightGold: '#D4AF37',
  cream: '#FDFBF7',
  lightCream: '#FFF9E6',
  white: '#FFFFFF',
  success: '#10B981',
  warning: '#F59E0B',
  danger: '#EF4444',
  critical: '#8B0000',
  text: '#1F2937'
};

const AdvancedReportsPanel = () => {
  const [downloading, setDownloading] = useState({});
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  const reports = [
    {
      id: 'enhanced_excel',
      name: 'Ultra-Premium Excel Report',
      description: '20+ detailed sheets with executive-grade formatting, comprehensive charts, heatmaps, and deep analysis',
      icon: FileSpreadsheet,
      color: 'gold',
      endpoint: '/reports/enhanced/excel',
      filename: 'ultra_comprehensive_compliance_report.xlsx',
      badge: '👑 RECOMMENDED',
      features: [
        '📊 Executive Summary Dashboard',
        '🎯 Risk Analysis & Heat Maps',
        '📋 Complete Rule-by-Rule Breakdown',
        '🔧 Detailed Remediation Strategies',
        '📈 Category & Severity Analysis',
        '⚠️ Failed/Passed Rules Deep Dive',
        '🔍 Framework Comparison Matrix',
        '📉 Gap Analysis & Trends',
        '⏱️ Timeline & Cost Estimates',
        '✅ Remediation Tracking Dashboard',
        '🎨 Professional Conditional Formatting',
        '💼 Audit-Ready Documentation'
      ]
    },
    {
      id: 'pdf',
      name: 'Executive PDF Report',
      description: '8+ page comprehensive PDF with charts, heatmaps, visualizations, and detailed technical analysis',
      icon: FileText,
      color: 'burgundy',
      endpoint: '/reports/download/pdf',
      filename: 'executive_compliance_report.pdf',
      badge: '📄 PREMIUM',
      features: [
        '📑 Executive Summary',
        '📊 Visual Compliance Dashboard',
        '🔥 Risk Heatmaps',
        '📈 Framework Analysis Charts',
        '⚠️ Priority Issues Breakdown',
        '🔧 Remediation Roadmap',
        '📉 Trend Analysis',
        '💼 Professional Formatting'
      ]
    },
    {
      id: 'json',
      name: 'Technical Data Export',
      description: 'Complete raw JSON data for API integration, custom processing, and automated workflows',
      icon: FileJson,
      color: 'blue',
      endpoint: '/reports/download/json',
      filename: 'compliance_data.json',
      badge: '🔧 TECHNICAL',
      features: [
        '💾 Complete Raw Data',
        '🔌 API Integration Ready',
        '⚙️ Custom Processing',
        '🤖 Machine Readable',
        '📦 All Audit Results',
        '🔍 Framework Details'
      ]
    }
  ];

  const getReportStyle = (color) => {
    const styles = {
      gold: {
        gradient: `linear-gradient(135deg, ${COLORS.lightGold}, ${COLORS.lightCream}, ${COLORS.lightGold})`,
        border: COLORS.gold,
        button: `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})`,
        icon: COLORS.gold,
        text: COLORS.darkGold
      },
      burgundy: {
        gradient: 'linear-gradient(135deg, #FEE2E2, #FECACA, #FEE2E2)',
        border: '#DC2626',
        button: 'linear-gradient(135deg, #DC2626, #991B1B)',
        icon: '#DC2626',
        text: '#991B1B'
      },
      blue: {
        gradient: 'linear-gradient(135deg, #DBEAFE, #BFDBFE, #DBEAFE)',
        border: '#3B82F6',
        button: 'linear-gradient(135deg, #3B82F6, #1D4ED8)',
        icon: '#3B82F6',
        text: '#1E40AF'
      }
    };
    return styles[color] || styles.gold;
  };

  const downloadReport = async (report) => {
    try {
      setDownloading(prev => ({ ...prev, [report.id]: true }));
      setError(null);
      setSuccess(null);

      const response = await axios.get(
        `${API_BASE_URL}${report.endpoint}`,
        { responseType: 'blob' }
      );

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', report.filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      setSuccess(`✅ ${report.name} downloaded successfully!`);
      setTimeout(() => setSuccess(null), 4000);

    } catch (err) {
      console.error(`Failed to download ${report.name}:`, err);
      setError(`❌ Failed to download ${report.name}. Please ensure a scan has been completed.`);
      setTimeout(() => setError(null), 6000);
    } finally {
      setDownloading(prev => ({ ...prev, [report.id]: false }));
    }
  };

  return (
    <div style={{
      padding: '32px',
      background: `linear-gradient(135deg, ${COLORS.lightCream}, ${COLORS.white}, ${COLORS.lightGold})`,
      minHeight: '100vh'
    }}>
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          background: `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})`,
          borderRadius: '24px',
          padding: '48px',
          color: COLORS.white,
          marginBottom: '32px',
          boxShadow: '0 20px 60px rgba(201, 169, 97, 0.4)',
          border: `3px solid ${COLORS.darkGold}`
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h1 style={{
              fontSize: '42px',
              fontWeight: 'bold',
              marginBottom: '12px',
              fontFamily: 'Georgia, serif',
              letterSpacing: '2px',
              textShadow: '2px 2px 4px rgba(0,0,0,0.3)'
            }}>
              ✨ Premium Reports Center
            </h1>
            <p style={{
              fontSize: '18px',
              color: 'rgba(255,255,255,0.95)',
              fontFamily: 'Georgia, serif',
              letterSpacing: '0.5px'
            }}>
              Download ultra-comprehensive compliance reports in multiple formats
            </p>
          </div>
          <Award size={64} style={{ opacity: 0.3 }} />
        </div>
      </motion.div>

      {/* Success Message */}
      <AnimatePresence>
        {success && (
          <motion.div
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.95 }}
            style={{
              background: 'linear-gradient(135deg, #D1FAE5, #A7F3D0)',
              border: `3px solid ${COLORS.success}`,
              borderRadius: '16px',
              padding: '20px',
              marginBottom: '24px',
              boxShadow: '0 8px 24px rgba(16, 185, 129, 0.3)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <CheckCircle size={24} color={COLORS.success} style={{ marginRight: '16px' }} />
              <p style={{
                color: '#065F46',
                fontSize: '16px',
                fontWeight: 'bold',
                fontFamily: 'Georgia, serif'
              }}>
                {success}
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Error Message */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.95 }}
            style={{
              background: 'linear-gradient(135deg, #FEE2E2, #FECACA)',
              border: `3px solid ${COLORS.danger}`,
              borderRadius: '16px',
              padding: '20px',
              marginBottom: '24px',
              boxShadow: '0 8px 24px rgba(239, 68, 68, 0.3)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <AlertTriangle size={24} color={COLORS.danger} style={{ marginRight: '16px' }} />
              <p style={{
                color: '#991B1B',
                fontSize: '16px',
                fontFamily: 'Georgia, serif'
              }}>
                {error}
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Report Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
        gap: '32px',
        marginBottom: '40px'
      }}>
        {reports.map((report, index) => {
          const style = getReportStyle(report.color);
          const Icon = report.icon;
          const isDownloading = downloading[report.id];
          const isRecommended = report.id === 'enhanced_excel';

          return (
            <motion.div
              key={report.id}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.15, type: 'spring', stiffness: 100 }}
              whileHover={{ scale: 1.03, y: -8 }}
              style={{
                background: `linear-gradient(135deg, ${COLORS.white}, ${COLORS.lightCream}, ${COLORS.white})`,
                borderRadius: '24px',
                overflow: 'hidden',
                border: `3px solid ${style.border}`,
                boxShadow: isRecommended
                  ? `0 20px 60px rgba(201, 169, 97, 0.4), 0 0 40px rgba(201, 169, 97, 0.2)`
                  : '0 10px 40px rgba(0, 0, 0, 0.1)',
                position: 'relative'
              }}
            >
              {/* Recommended Badge */}
              {isRecommended && (
                <div style={{
                  position: 'absolute',
                  top: '-12px',
                  right: '24px',
                  background: `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})`,
                  color: COLORS.white,
                  padding: '8px 20px',
                  borderRadius: '20px',
                  fontSize: '12px',
                  fontWeight: 'bold',
                  boxShadow: '0 4px 12px rgba(201, 169, 97, 0.4)',
                  zIndex: 10,
                  fontFamily: 'Georgia, serif',
                  letterSpacing: '1px'
                }}>
                  <Sparkles size={14} style={{ display: 'inline', marginRight: '4px' }} />
                  BEST VALUE
                </div>
              )}

              {/* Card Header */}
              <div style={{
                background: style.gradient,
                borderBottom: `3px solid ${style.border}`,
                padding: '32px'
              }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '16px' }}>
                  <div style={{
                    padding: '16px',
                    background: style.button,
                    borderRadius: '16px',
                    boxShadow: '0 8px 24px rgba(0, 0, 0, 0.2)'
                  }}>
                    <Icon size={40} color={COLORS.white} />
                  </div>
                  <span style={{
                    fontSize: '11px',
                    padding: '6px 16px',
                    color: style.text,
                    background: COLORS.white,
                    borderRadius: '20px',
                    fontWeight: 'bold',
                    border: `2px solid ${style.border}`,
                    fontFamily: 'Georgia, serif',
                    letterSpacing: '0.5px'
                  }}>
                    {report.badge}
                  </span>
                </div>

                <h3 style={{
                  fontSize: '24px',
                  fontWeight: 'bold',
                  color: style.text,
                  marginBottom: '12px',
                  fontFamily: 'Georgia, serif',
                  letterSpacing: '0.5px'
                }}>
                  {report.name}
                </h3>
                <p style={{
                  color: '#4B5563',
                  fontSize: '14px',
                  lineHeight: '1.6',
                  fontFamily: 'Georgia, serif'
                }}>
                  {report.description}
                </p>
              </div>

              {/* Card Body */}
              <div style={{ padding: '32px' }}>
                <h4 style={{
                  fontWeight: 'bold',
                  color: COLORS.text,
                  marginBottom: '16px',
                  fontSize: '16px',
                  fontFamily: 'Georgia, serif'
                }}>
                  ✨ Premium Features:
                </h4>
                <ul style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                  marginBottom: '32px'
                }}>
                  {report.features.map((feature, idx) => (
                    <motion.li
                      key={idx}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.1 + idx * 0.05 }}
                      style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        fontSize: '14px',
                        color: '#374151',
                        fontFamily: 'Georgia, serif'
                      }}
                    >
                      <CheckCircle size={18} color={COLORS.success} style={{ marginRight: '12px', marginTop: '2px', flexShrink: 0 }} />
                      <span>{feature}</span>
                    </motion.li>
                  ))}
                </ul>

                <motion.button
                  onClick={() => downloadReport(report)}
                  disabled={isDownloading}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  style={{
                    width: '100%',
                    padding: '18px 32px',
                    background: isDownloading ? '#9CA3AF' : style.button,
                    color: COLORS.white,
                    borderRadius: '16px',
                    border: 'none',
                    cursor: isDownloading ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 'bold',
                    fontSize: '16px',
                    boxShadow: '0 8px 24px rgba(0, 0, 0, 0.2)',
                    fontFamily: 'Georgia, serif',
                    letterSpacing: '0.5px',
                    opacity: isDownloading ? 0.6 : 1
                  }}
                >
                  {isDownloading ? (
                    <>
                      <Loader size={20} style={{ marginRight: '12px', animation: 'spin 1s linear infinite' }} />
                      Generating Premium Report...
                    </>
                  ) : (
                    <>
                      <Download size={20} style={{ marginRight: '12px' }} />
                      Download {report.name.split(' ')[0]}
                    </>
                  )}
                </motion.button>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Info Boxes */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))',
        gap: '24px',
        marginBottom: '32px'
      }}>
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.4 }}
          style={{
            background: `linear-gradient(135deg, ${COLORS.lightGold}, ${COLORS.lightCream})`,
            border: `3px solid ${COLORS.gold}`,
            borderRadius: '20px',
            padding: '32px',
            boxShadow: '0 10px 40px rgba(201, 169, 97, 0.3)'
          }}
        >
          <h4 style={{
            fontWeight: 'bold',
            color: COLORS.darkGold,
            marginBottom: '16px',
            display: 'flex',
            alignItems: 'center',
            fontSize: '18px',
            fontFamily: 'Georgia, serif'
          }}>
            <FileSpreadsheet size={24} style={{ marginRight: '12px' }} />
            Ultra-Premium Excel Report
          </h4>
          <p style={{
            fontSize: '14px',
            color: '#374151',
            lineHeight: '1.8',
            fontFamily: 'Georgia, serif'
          }}>
            The <strong>Ultra-Premium Excel Report</strong> is our flagship offering, featuring <strong>20+ professionally formatted sheets</strong> including executive dashboard, comprehensive risk analysis, complete rule-by-rule breakdown, detailed remediation strategies, heatmaps, gap analysis, and timeline roadmaps. Perfect for C-level presentations, audit submissions, and detailed compliance tracking.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
          style={{
            background: 'linear-gradient(135deg, #FEE2E2, #FECACA)',
            border: '3px solid #DC2626',
            borderRadius: '20px',
            padding: '32px',
            boxShadow: '0 10px 40px rgba(220, 38, 38, 0.3)'
          }}
        >
          <h4 style={{
            fontWeight: 'bold',
            color: '#991B1B',
            marginBottom: '16px',
            display: 'flex',
            alignItems: 'center',
            fontSize: '18px',
            fontFamily: 'Georgia, serif'
          }}>
            <FileText size={24} style={{ marginRight: '12px' }} />
            Executive PDF Report
          </h4>
          <p style={{
            fontSize: '14px',
            color: '#374151',
            lineHeight: '1.8',
            fontFamily: 'Georgia, serif'
          }}>
            The <strong>Executive PDF Report</strong> provides a comprehensive <strong>8+ page document</strong> with visual dashboards, risk heatmaps, detailed charts, framework analysis, priority issues breakdown, and remediation roadmaps. Professionally formatted for board meetings, stakeholder presentations, and regulatory submissions.
          </p>
        </motion.div>
      </div>

      {/* Usage Tips */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        style={{
          background: `linear-gradient(135deg, ${COLORS.white}, ${COLORS.lightCream}, ${COLORS.white})`,
          border: `3px solid ${COLORS.gold}`,
          borderRadius: '24px',
          padding: '40px',
          boxShadow: '0 10px 40px rgba(201, 169, 97, 0.2)'
        }}
      >
        <h4 style={{
          fontWeight: 'bold',
          color: COLORS.darkGold,
          marginBottom: '24px',
          fontSize: '24px',
          fontFamily: 'Georgia, serif',
          textAlign: 'center',
          letterSpacing: '1px'
        }}>
          📋 Premium Report Usage Guide
        </h4>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: '24px'
        }}>
          {[
            {
              title: '👔 For C-Level Executives',
              content: 'Use the Ultra-Premium Excel or Executive PDF reports for high-level strategic overviews, board presentations, and investment decisions.',
              icon: Shield
            },
            {
              title: '🔧 For Technical Teams',
              content: 'Use the Ultra-Premium Excel report for detailed remediation planning, implementation tracking, and technical deep-dives.',
              icon: TrendingUp
            },
            {
              title: '📊 For Compliance Officers',
              content: 'Use the Ultra-Premium Excel report for audit trails, regulatory submissions, and comprehensive compliance documentation.',
              icon: Award
            },
            {
              title: '💻 For Developers',
              content: 'Use the Technical JSON export for custom integrations, automated workflows, and API-based processing.',
              icon: FileJson
            }
          ].map((tip, idx) => (
            <motion.div
              key={idx}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.7 + idx * 0.1 }}
              style={{
                background: `linear-gradient(135deg, ${COLORS.lightCream}, ${COLORS.white})`,
                border: `2px solid ${COLORS.lightGold}`,
                borderRadius: '16px',
                padding: '24px',
                boxShadow: '0 4px 12px rgba(201, 169, 97, 0.15)'
              }}
            >
              <h5 style={{
                fontWeight: 'bold',
                marginBottom: '12px',
                color: COLORS.darkGold,
                fontSize: '16px',
                fontFamily: 'Georgia, serif'
              }}>
                {tip.title}
              </h5>
              <p style={{
                fontSize: '14px',
                color: '#4B5563',
                lineHeight: '1.6',
                fontFamily: 'Georgia, serif'
              }}>
                {tip.content}
              </p>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </div>
  );
};

export default AdvancedReportsPanel;

