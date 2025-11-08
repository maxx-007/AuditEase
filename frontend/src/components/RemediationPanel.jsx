import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import {
  Download,
  Loader,
  AlertTriangle,
  Code,
  Info,
  ChevronDown,
  ChevronRight,
  Monitor,
  Apple,
  Terminal,
  Shield,
  CheckCircle
} from 'lucide-react';

// Use relative URL to work with Vite proxy - this prevents /api/api duplication
const API_BASE_URL = '/api';

// Luxury color scheme matching other components
const COLORS = {
  gold: '#C9A961',
  darkGold: '#B8860B',
  lightGold: '#D4AF37',
  cream: '#FDFBF7',
  lightCream: '#FFF9E6',
  critical: '#8B0000',
  high: '#FF4444',
  medium: '#FFA500',
  low: '#00CC00',
  white: '#FFFFFF'
};

const RemediationPanel = () => {
  const [guidance, setGuidance] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedPlatform, setSelectedPlatform] = useState('linux');
  const [expandedItems, setExpandedItems] = useState(new Set());
  const [downloadingScripts, setDownloadingScripts] = useState(false);
  const [detectedOS, setDetectedOS] = useState(null);

  // OS Detection
  useEffect(() => {
    const detectOS = () => {
      const userAgent = navigator.userAgent.toLowerCase();
      const platform = navigator.platform.toLowerCase();
      
      if (userAgent.includes('win') || platform.includes('win')) {
        return 'windows';
      } else if (userAgent.includes('mac') || platform.includes('mac')) {
        return 'macos';
      } else if (userAgent.includes('linux') || platform.includes('linux')) {
        return 'linux';
      }
      return 'linux'; // default fallback
    };
    
    setDetectedOS(detectOS());
  }, []);

  // Load remediation guidance on component mount
  useEffect(() => {
    loadRemediationGuidance();
  }, []);

  const loadRemediationGuidance = async () => {
    try {
      setLoading(true);
      setError(null);

      console.log('🔄 Loading remediation guidance from:', `${API_BASE_URL}/remediation/guidance`);

      const response = await axios.get(`${API_BASE_URL}/remediation/guidance`);
      const data = response.data;

      console.log('✅ Remediation guidance response:', {
        total_items: data.total_items,
        guidance_count: data.guidance?.length,
        source_file: data.source_file,
        timestamp: data.timestamp
      });

      if (data.guidance && data.guidance.length > 0) {
        setGuidance(data.guidance);
        console.log(`📋 Loaded ${data.guidance.length} remediation items`);
      } else {
        setGuidance([]);
        const message = data.message || 'No remediation guidance available. Please run a compliance scan first.';
        setError(message);
        console.warn('⚠️ No guidance items found:', message);
      }
    } catch (err) {
      console.error('❌ Failed to load remediation guidance:', {
        message: err.message,
        response: err.response?.data,
        status: err.response?.status,
        url: err.config?.url
      });

      let errorMessage = 'Failed to load remediation guidance. ';

      if (err.response?.status === 404) {
        errorMessage += 'No audit results found. Please run a compliance scan first.';
      } else if (err.response?.status === 500) {
        errorMessage += `Server error: ${err.response?.data?.detail || 'Unknown error'}`;
      } else if (err.code === 'ERR_NETWORK') {
        errorMessage += 'Cannot connect to backend server. Please ensure the backend is running.';
      } else {
        errorMessage += err.message || 'Please try again.';
      }

      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const platforms = [
    {
      id: 'linux',
      name: 'Linux',
      icon: '🐧',
      description: 'Comprehensive Linux hardening script',
      details: 'Includes ISO 27001, CIS Controls, and RBI Guidelines compliance'
    },
    {
      id: 'windows',
      name: 'Windows',
      icon: '🪟',
      description: 'PowerShell-based Windows hardening',
      details: 'Windows 10/11/Server 2016/2019/2022 compatible'
    },
    {
      id: 'macos',
      name: 'macOS',
      icon: '🍎',
      description: 'macOS security configuration script',
      details: 'Enterprise-grade macOS security hardening'
    }
  ];

  const downloadScripts = async (platform) => {
    try {
      setDownloadingScripts(true);
      setError(null);

      console.log(`📥 Downloading ${platform} remediation scripts...`);

      // Generate and download scripts
      const response = await axios.get(
        `${API_BASE_URL}/remediation/scripts/${platform}/download`,
        { responseType: 'blob' }
      );

      console.log('✅ Scripts downloaded successfully:', {
        size: response.data.size,
        type: response.data.type
      });

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `remediation_scripts_${platform}.zip`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      console.log(`💾 Saved as: remediation_scripts_${platform}.zip`);

    } catch (error) {
      console.error('❌ Download failed:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });

      let errorMessage = 'Failed to download scripts. ';

      if (error.response?.status === 404) {
        errorMessage += 'Scripts not found. Please try again.';
      } else if (error.response?.status === 400) {
        errorMessage += 'Invalid platform selected.';
      } else if (error.response?.status === 500) {
        errorMessage += 'Server error generating scripts.';
      } else if (error.code === 'ERR_NETWORK') {
        errorMessage += 'Cannot connect to backend server.';
      } else {
        errorMessage += 'Please try again.';
      }

      setError(errorMessage);
    } finally {
      setDownloadingScripts(false);
    }
  };

  // Platform selection with OS detection highlighting - LUXURY DESIGN WITH INLINE STYLES
  const renderPlatformSelector = () => (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(3, 1fr)',
      gap: '24px',
      marginBottom: '32px'
    }}>
      {platforms.map((platform) => {
        const isRecommended = detectedOS === platform.id;
        const isSelected = selectedPlatform === platform.id;

        return (
          <motion.div
            key={platform.id}
            onClick={() => setSelectedPlatform(platform.id)}
            whileHover={{ scale: 1.05, y: -8 }}
            whileTap={{ scale: 0.98 }}
            style={{
              position: 'relative',
              padding: '32px',
              borderRadius: '20px',
              cursor: 'pointer',
              background: isSelected
                ? `linear-gradient(135deg, ${COLORS.lightCream}, ${COLORS.lightGold}, ${COLORS.lightCream})`
                : `linear-gradient(135deg, ${COLORS.white}, ${COLORS.cream})`,
              border: `3px solid ${isSelected ? COLORS.gold : 'rgba(201, 169, 97, 0.3)'}`,
              boxShadow: isSelected
                ? `0 20px 60px rgba(201, 169, 97, 0.4), 0 0 40px rgba(201, 169, 97, 0.2)`
                : isRecommended
                ? `0 10px 40px rgba(201, 169, 97, 0.3), 0 0 0 4px rgba(201, 169, 97, 0.2)`
                : '0 4px 20px rgba(0, 0, 0, 0.1)',
              transition: 'all 0.4s ease',
              zIndex: isSelected ? 20 : isRecommended ? 15 : 10
            }}
          >
            {/* Recommended Badge */}
            {isRecommended && (
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                style={{
                  position: 'absolute',
                  top: '-12px',
                  right: '-12px',
                  background: `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})`,
                  color: COLORS.white,
                  fontSize: '11px',
                  padding: '6px 16px',
                  borderRadius: '20px',
                  fontWeight: 'bold',
                  boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  border: `2px solid ${COLORS.white}`,
                  fontFamily: 'Georgia, serif',
                  letterSpacing: '1px',
                  zIndex: 30
                }}
              >
                <span style={{ fontSize: '16px' }}>✨</span>
                <span>RECOMMENDED</span>
              </motion.div>
            )}

            {/* Selection Indicator */}
            {isSelected && (
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                style={{
                  position: 'absolute',
                  top: '-10px',
                  left: '-10px',
                  width: '32px',
                  height: '32px',
                  background: `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})`,
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
                  border: `3px solid ${COLORS.white}`,
                  zIndex: 30
                }}
              >
                <CheckCircle size={18} color={COLORS.white} />
              </motion.div>
            )}

            {/* Card Content */}
            <div style={{ textAlign: 'center', position: 'relative', zIndex: 10 }}>
              <div style={{
                fontSize: '64px',
                marginBottom: '16px',
                transform: isSelected ? 'scale(1.1)' : 'scale(1)',
                transition: 'transform 0.3s ease'
              }}>
                {platform.icon}
              </div>
              <div style={{
                fontWeight: 'bold',
                fontSize: '22px',
                marginBottom: '8px',
                color: isSelected ? COLORS.darkGold : '#333',
                fontFamily: 'Georgia, serif',
                letterSpacing: '0.5px'
              }}>
                {platform.name}
              </div>
              <div style={{
                fontSize: '14px',
                color: '#666',
                marginBottom: '8px',
                fontWeight: '600'
              }}>
                {platform.description}
              </div>
              <div style={{
                fontSize: '12px',
                color: '#888',
                fontStyle: 'italic',
                lineHeight: '1.6'
              }}>
                {platform.details}
              </div>
            </div>

            {/* Animated Corner Accent */}
            {isSelected && (
              <>
                <div style={{
                  position: 'absolute',
                  top: 0,
                  right: 0,
                  width: '80px',
                  height: '80px',
                  background: 'linear-gradient(to bottom right, rgba(201, 169, 97, 0.2), transparent)',
                  borderRadius: '20px',
                  pointerEvents: 'none'
                }}></div>
                <div style={{
                  position: 'absolute',
                  bottom: 0,
                  left: 0,
                  width: '80px',
                  height: '80px',
                  background: 'linear-gradient(to top right, rgba(201, 169, 97, 0.2), transparent)',
                  borderRadius: '20px',
                  pointerEvents: 'none'
                }}></div>
              </>
            )}
          </motion.div>
        );
      })}
    </div>
  );

  if (loading) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '400px',
          background: `linear-gradient(135deg, ${COLORS.lightCream}, ${COLORS.white}, ${COLORS.lightGold})`,
          borderRadius: '20px',
          border: `3px solid ${COLORS.gold}`,
          boxShadow: '0 10px 40px rgba(201, 169, 97, 0.3)'
        }}
      >
        <div style={{ textAlign: 'center' }}>
          <Loader
            size={56}
            style={{
              animation: 'spin 1s linear infinite',
              color: COLORS.gold,
              margin: '0 auto 24px'
            }}
          />
          <div style={{
            fontSize: '24px',
            fontWeight: 'bold',
            color: COLORS.darkGold,
            fontFamily: 'Georgia, serif',
            marginBottom: '8px'
          }}>
            Loading Remediation Guidance...
          </div>
          <p style={{
            fontSize: '16px',
            color: '#666',
            fontFamily: 'Georgia, serif'
          }}>
            Preparing your premium compliance solutions
          </p>
        </div>
      </motion.div>
    );
  }

  if (error) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        style={{
          background: 'linear-gradient(135deg, #FEE2E2, #FFFFFF, #FEE2E2)',
          border: '3px solid #DC2626',
          borderRadius: '20px',
          padding: '40px',
          boxShadow: '0 20px 60px rgba(220, 38, 38, 0.2)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: '24px' }}>
          <div style={{
            width: '56px',
            height: '56px',
            background: '#FEE2E2',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginRight: '20px'
          }}>
            <AlertTriangle size={32} color="#DC2626" />
          </div>
          <h3 style={{
            fontSize: '28px',
            fontWeight: 'bold',
            color: '#991B1B',
            fontFamily: 'Georgia, serif'
          }}>
            Unable to Load Guidance
          </h3>
        </div>
        <p style={{
          color: '#B91C1C',
          marginBottom: '24px',
          fontSize: '18px',
          lineHeight: '1.6'
        }}>
          {error}
        </p>
        <motion.button
          onClick={loadRemediationGuidance}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          style={{
            padding: '14px 32px',
            background: 'linear-gradient(135deg, #DC2626, #991B1B)',
            color: COLORS.white,
            borderRadius: '12px',
            fontWeight: 'bold',
            fontSize: '16px',
            border: 'none',
            cursor: 'pointer',
            boxShadow: '0 8px 24px rgba(220, 38, 38, 0.3)',
            fontFamily: 'Georgia, serif'
          }}
        >
          Retry Loading
        </motion.button>
      </motion.div>
    );
  }

  const toggleExpanded = (index) => {
    const newExpanded = new Set(expandedItems);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedItems(newExpanded);
  };

  const renderGuidanceItem = (item, index) => {
    const isExpanded = expandedItems.has(index);
    const guidance = item.guidance;

    const getSeverityStyle = (severity) => {
      const styles = {
        'CRITICAL': { background: 'linear-gradient(135deg, #DC2626, #991B1B)', color: COLORS.white },
        'HIGH': { background: 'linear-gradient(135deg, #F97316, #EA580C)', color: COLORS.white },
        'MEDIUM': { background: `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})`, color: COLORS.white },
        'LOW': { background: 'linear-gradient(135deg, #3B82F6, #2563EB)', color: COLORS.white }
      };
      return styles[severity] || styles['LOW'];
    };

    const getPriorityStyle = (priority) => {
      const styles = {
        'P0': { background: 'linear-gradient(135deg, #DC2626, #991B1B)', border: '2px solid #FCA5A5' },
        'P1': { background: 'linear-gradient(135deg, #F97316, #EA580C)', border: '2px solid #FDBA74' },
        'P2': { background: `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})`, border: `2px solid ${COLORS.lightGold}` },
        'P3': { background: 'linear-gradient(135deg, #3B82F6, #2563EB)', border: '2px solid #93C5FD' }
      };
      return styles[priority] || styles['P3'];
    };

    return (
      <motion.div
        key={index}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: index * 0.1 }}
        style={{
          background: `linear-gradient(135deg, ${COLORS.white}, ${COLORS.lightCream}, ${COLORS.white})`,
          border: `3px solid ${COLORS.gold}`,
          borderRadius: '20px',
          padding: '32px',
          boxShadow: '0 10px 40px rgba(201, 169, 97, 0.2)',
          marginBottom: '24px',
          transition: 'all 0.3s ease'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div style={{
              padding: '10px 20px',
              borderRadius: '12px',
              fontSize: '14px',
              fontWeight: 'bold',
              boxShadow: '0 4px 12px rgba(0, 0, 0, 0.2)',
              fontFamily: 'Georgia, serif',
              ...getSeverityStyle(guidance.severity)
            }}>
              {guidance.severity}
            </div>
            <div style={{
              padding: '10px 20px',
              borderRadius: '12px',
              fontSize: '14px',
              fontWeight: 'bold',
              boxShadow: '0 4px 12px rgba(0, 0, 0, 0.2)',
              color: COLORS.white,
              fontFamily: 'Georgia, serif',
              ...getPriorityStyle(guidance.priority)
            }}>
              {guidance.priority}
            </div>
          </div>
          <motion.button
            onClick={() => toggleExpanded(index)}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            style={{
              display: 'flex',
              alignItems: 'center',
              color: COLORS.darkGold,
              background: COLORS.lightCream,
              padding: '12px 20px',
              borderRadius: '12px',
              border: `2px solid ${COLORS.gold}`,
              cursor: 'pointer',
              fontWeight: 'bold',
              fontFamily: 'Georgia, serif'
            }}
          >
            {isExpanded ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
          </motion.button>
        </div>

        <div style={{ marginBottom: '20px' }}>
          <h4 style={{
            fontSize: '22px',
            fontWeight: 'bold',
            color: COLORS.darkGold,
            marginBottom: '16px',
            display: 'flex',
            alignItems: 'center',
            fontFamily: 'Georgia, serif'
          }}>
            <span style={{
              width: '10px',
              height: '10px',
              background: COLORS.gold,
              borderRadius: '50%',
              marginRight: '12px'
            }}></span>
            {item.framework} - {guidance.rule_id}
          </h4>
          <p style={{
            color: '#374151',
            fontSize: '16px',
            lineHeight: '1.8',
            paddingLeft: '22px',
            fontFamily: 'Georgia, serif'
          }}>
            {guidance.description}
          </p>
        </div>

        {isExpanded && (
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '24px',
            borderTop: `3px solid ${COLORS.gold}`,
            paddingTop: '24px',
            marginTop: '20px'
          }}>
            {/* Impact Analysis */}
            <div style={{
              background: `linear-gradient(135deg, ${COLORS.lightCream}, ${COLORS.lightGold})`,
              padding: '24px',
              borderRadius: '16px',
              border: `2px solid ${COLORS.gold}`,
              boxShadow: '0 4px 12px rgba(201, 169, 97, 0.2)'
            }}>
              <h5 style={{
                fontWeight: 'bold',
                color: COLORS.darkGold,
                marginBottom: '16px',
                display: 'flex',
                alignItems: 'center',
                fontSize: '18px',
                fontFamily: 'Georgia, serif'
              }}>
                <span style={{ fontSize: '28px', marginRight: '12px' }}>💡</span>
                Impact Analysis
              </h5>
              <p style={{
                color: '#374151',
                lineHeight: '1.8',
                fontFamily: 'Georgia, serif'
              }}>
                {guidance.impact_analysis}
              </p>
            </div>

            {/* Remediation Steps */}
            <div style={{
              background: 'linear-gradient(135deg, #EFF6FF, #DBEAFE)',
              padding: '24px',
              borderRadius: '16px',
              border: '2px solid #3B82F6',
              boxShadow: '0 4px 12px rgba(59, 130, 246, 0.2)'
            }}>
              <h5 style={{
                fontWeight: 'bold',
                color: '#1E3A8A',
                marginBottom: '16px',
                display: 'flex',
                alignItems: 'center',
                fontSize: '18px',
                fontFamily: 'Georgia, serif'
              }}>
                <span style={{ fontSize: '28px', marginRight: '12px' }}>📝</span>
                Remediation Steps
              </h5>
              <ol style={{
                listStyleType: 'decimal',
                listStylePosition: 'inside',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px'
              }}>
                {guidance.remediation_steps.map((step, stepIndex) => (
                  <li key={stepIndex} style={{
                    color: '#374151',
                    fontWeight: '500',
                    paddingLeft: '8px',
                    fontFamily: 'Georgia, serif',
                    lineHeight: '1.6'
                  }}>
                    {step}
                  </li>
                ))}
              </ol>
            </div>

            {/* Effort and Timeline Grid */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '20px'
            }}>
              <div style={{
                background: 'linear-gradient(135deg, #FAE8FF, #F3E8FF)',
                padding: '20px',
                borderRadius: '16px',
                border: '2px solid #A855F7',
                boxShadow: '0 4px 12px rgba(168, 85, 247, 0.2)'
              }}>
                <h5 style={{
                  fontWeight: 'bold',
                  color: '#581C87',
                  marginBottom: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  fontFamily: 'Georgia, serif'
                }}>
                  <span style={{ fontSize: '24px', marginRight: '8px' }}>⏱️</span>
                  Effort Estimate
                </h5>
                <p style={{
                  color: '#374151',
                  fontWeight: 'bold',
                  fontSize: '16px',
                  fontFamily: 'Georgia, serif'
                }}>
                  {guidance.effort_estimate}
                </p>
              </div>
              <div style={{
                background: 'linear-gradient(135deg, #D1FAE5, #A7F3D0)',
                padding: '20px',
                borderRadius: '16px',
                border: '2px solid #10B981',
                boxShadow: '0 4px 12px rgba(16, 185, 129, 0.2)'
              }}>
                <h5 style={{
                  fontWeight: 'bold',
                  color: '#065F46',
                  marginBottom: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  fontFamily: 'Georgia, serif'
                }}>
                  <span style={{ fontSize: '24px', marginRight: '8px' }}>📅</span>
                  Timeline
                </h5>
                <p style={{
                  color: '#374151',
                  fontWeight: 'bold',
                  fontSize: '16px',
                  fontFamily: 'Georgia, serif'
                }}>
                  {guidance.timeline}
                </p>
              </div>
            </div>

            {/* Available Scripts */}
            {guidance.scripts && guidance.scripts.length > 0 && (
              <div style={{
                background: 'linear-gradient(135deg, #F1F5F9, #E2E8F0)',
                padding: '24px',
                borderRadius: '16px',
                border: '2px solid #64748B',
                boxShadow: '0 4px 12px rgba(100, 116, 139, 0.2)'
              }}>
                <h5 style={{
                  fontWeight: 'bold',
                  color: '#1E293B',
                  marginBottom: '16px',
                  display: 'flex',
                  alignItems: 'center',
                  fontSize: '18px',
                  fontFamily: 'Georgia, serif'
                }}>
                  <span style={{ fontSize: '28px', marginRight: '12px' }}>💻</span>
                  Available Scripts
                </h5>
                <div style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: '12px'
                }}>
                  {guidance.scripts.map((script, scriptIndex) => (
                    <div key={scriptIndex} style={{
                      display: 'flex',
                      alignItems: 'center',
                      background: `linear-gradient(135deg, ${COLORS.lightGold}, ${COLORS.lightCream})`,
                      padding: '10px 16px',
                      borderRadius: '12px',
                      border: `2px solid ${COLORS.gold}`,
                      boxShadow: '0 2px 8px rgba(201, 169, 97, 0.2)'
                    }}>
                      <Code size={20} color={COLORS.darkGold} style={{ marginRight: '8px' }} />
                      <span style={{
                        fontSize: '14px',
                        fontWeight: 'bold',
                        color: COLORS.darkGold,
                        fontFamily: 'Georgia, serif'
                      }}>
                        {script.name} ({script.platform})
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </motion.div>
    );
  };

  return (
    <div style={{
      padding: '32px',
      background: `linear-gradient(135deg, ${COLORS.lightCream}, ${COLORS.white}, ${COLORS.lightGold})`,
      minHeight: '100vh'
    }}>
      {/* Luxury Header Section */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          background: `linear-gradient(135deg, ${COLORS.white}, ${COLORS.lightCream}, ${COLORS.white})`,
          borderRadius: '24px',
          boxShadow: `0 20px 60px rgba(201, 169, 97, 0.3)`,
          padding: '48px',
          border: `3px solid ${COLORS.gold}`,
          marginBottom: '32px'
        }}
      >
        {/* Title with Royal Styling */}
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <h2 style={{
            fontSize: '42px',
            fontWeight: 'bold',
            background: `linear-gradient(135deg, ${COLORS.darkGold}, ${COLORS.gold}, ${COLORS.darkGold})`,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            marginBottom: '12px',
            fontFamily: 'Georgia, serif',
            letterSpacing: '2px'
          }}>
            ✨ Remediation Center ✨
          </h2>
          <div style={{
            height: '4px',
            width: '120px',
            background: `linear-gradient(to right, transparent, ${COLORS.gold}, transparent)`,
            margin: '0 auto',
            borderRadius: '4px'
          }}></div>
        </div>

        {/* OS Detection Banner */}
        {detectedOS && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            style={{
              marginBottom: '32px',
              padding: '20px',
              background: `linear-gradient(135deg, ${COLORS.lightGold}, ${COLORS.lightCream}, ${COLORS.lightGold})`,
              border: `3px solid ${COLORS.gold}`,
              borderRadius: '16px',
              boxShadow: '0 8px 24px rgba(201, 169, 97, 0.3)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div style={{
                width: '48px',
                height: '48px',
                background: `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})`,
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginRight: '16px',
                boxShadow: '0 4px 12px rgba(0, 0, 0, 0.2)'
              }}>
                <Info size={24} color={COLORS.white} />
              </div>
              <span style={{
                color: COLORS.darkGold,
                fontWeight: 'bold',
                fontSize: '18px',
                fontFamily: 'Georgia, serif'
              }}>
                Detected OS: <strong style={{ color: COLORS.gold }}>{platforms.find(p => p.id === detectedOS)?.name}</strong>
                <span style={{ color: '#666', marginLeft: '12px', fontSize: '16px' }}>(Recommended platform highlighted)</span>
              </span>
            </div>
          </motion.div>
        )}

        {/* Platform Selector */}
        {renderPlatformSelector()}

        {/* Luxury Download Button */}
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '20px',
          marginTop: '40px'
        }}>
          <motion.button
            onClick={() => downloadScripts(selectedPlatform)}
            disabled={downloadingScripts}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            style={{
              position: 'relative',
              padding: '20px 48px',
              background: `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})`,
              color: COLORS.white,
              borderRadius: '16px',
              fontWeight: 'bold',
              fontSize: '20px',
              border: `3px solid ${COLORS.darkGold}`,
              cursor: downloadingScripts ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              boxShadow: `0 20px 60px rgba(201, 169, 97, 0.4)`,
              fontFamily: 'Georgia, serif',
              letterSpacing: '0.5px',
              opacity: downloadingScripts ? 0.6 : 1
            }}
          >
            {downloadingScripts ? (
              <>
                <Loader size={28} style={{ marginRight: '12px', animation: 'spin 1s linear infinite' }} />
                <span>Generating Premium Scripts...</span>
              </>
            ) : (
              <>
                <Download size={28} style={{ marginRight: '12px' }} />
                <span>Download {platforms.find(p => p.id === selectedPlatform)?.name} Hardening Scripts</span>
              </>
            )}
          </motion.button>
          <div style={{
            textAlign: 'center',
            background: `linear-gradient(135deg, ${COLORS.lightGold}, ${COLORS.lightCream})`,
            padding: '16px 32px',
            borderRadius: '12px',
            border: `2px solid ${COLORS.gold}`,
            boxShadow: '0 4px 12px rgba(201, 169, 97, 0.2)'
          }}>
            <p style={{
              fontWeight: 'bold',
              color: COLORS.darkGold,
              fontSize: '14px',
              fontFamily: 'Georgia, serif',
              marginBottom: '4px'
            }}>
              ✨ Premium Comprehensive OS Hardening Scripts
            </p>
            <p style={{
              fontSize: '12px',
              color: '#666',
              fontFamily: 'Georgia, serif'
            }}>
              ISO 27001 • CIS Controls v8 • RBI Guidelines Compliance
            </p>
          </div>
        </div>
      </motion.div>

      {/* Remediation Guidance Section */}
      {guidance.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: `linear-gradient(135deg, ${COLORS.lightGold}, ${COLORS.lightCream})`,
              padding: '24px 32px',
              borderRadius: '16px',
              border: `3px solid ${COLORS.gold}`,
              boxShadow: '0 8px 24px rgba(201, 169, 97, 0.3)'
            }}
          >
            <h3 style={{
              fontSize: '28px',
              fontWeight: 'bold',
              color: COLORS.darkGold,
              fontFamily: 'Georgia, serif',
              letterSpacing: '1px'
            }}>
              📋 Remediation Guidance
            </h3>
            <div style={{
              padding: '12px 24px',
              background: `linear-gradient(135deg, ${COLORS.gold}, ${COLORS.darkGold})`,
              color: COLORS.white,
              borderRadius: '12px',
              fontWeight: 'bold',
              fontSize: '16px',
              boxShadow: '0 4px 12px rgba(0, 0, 0, 0.2)',
              fontFamily: 'Georgia, serif'
            }}>
              {guidance.length} Items
            </div>
          </motion.div>
          {guidance.map((item, index) => renderGuidanceItem(item, index))}
        </div>
      )}

      {/* No Items Message */}
      {guidance.length === 0 && !loading && !error && (
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          style={{
            background: 'linear-gradient(135deg, #D1FAE5, #FFFFFF, #A7F3D0)',
            border: '3px solid #10B981',
            borderRadius: '20px',
            padding: '48px',
            textAlign: 'center',
            boxShadow: '0 20px 60px rgba(16, 185, 129, 0.2)'
          }}
        >
          <div style={{
            width: '80px',
            height: '80px',
            background: 'linear-gradient(135deg, #10B981, #059669)',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 24px',
            boxShadow: '0 8px 24px rgba(16, 185, 129, 0.3)'
          }}>
            <Shield size={40} color={COLORS.white} />
          </div>
          <h3 style={{
            fontSize: '32px',
            fontWeight: 'bold',
            color: '#065F46',
            marginBottom: '12px',
            fontFamily: 'Georgia, serif'
          }}>
            ✨ Perfect Compliance Status
          </h3>
          <p style={{
            color: '#047857',
            fontSize: '18px',
            fontFamily: 'Georgia, serif'
          }}>
            All compliance checks are passing! No remediation needed.
          </p>
        </motion.div>
      )}
    </div>
  );
};

export default RemediationPanel;

