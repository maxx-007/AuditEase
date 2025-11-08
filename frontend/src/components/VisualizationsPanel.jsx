import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  BarChart3, 
  PieChart, 
  TrendingUp, 
  Download, 
  Loader, 
  AlertTriangle,
  ExternalLink,
  Image as ImageIcon,
  Grid
} from 'lucide-react';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const VisualizationsPanel = () => {
  const [visualizations, setVisualizations] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedViz, setSelectedViz] = useState(null);
  const [generating, setGenerating] = useState(false);

  const vizTypes = [
    {
      id: 'dashboard',
      name: 'Interactive Dashboard',
      description: 'Comprehensive Plotly dashboard with multiple charts',
      icon: Grid,
      color: 'blue',
      type: 'html'
    },
    {
      id: 'heatmap',
      name: 'Compliance Heatmap',
      description: 'Visual heatmap of compliance across frameworks',
      icon: BarChart3,
      color: 'green',
      type: 'image'
    },
    {
      id: 'gap_analysis',
      name: 'Gap Analysis',
      description: 'Current vs target compliance visualization',
      icon: TrendingUp,
      color: 'orange',
      type: 'image'
    },
    {
      id: 'risk_distribution',
      name: 'Risk Distribution',
      description: 'Severity breakdown across frameworks',
      icon: PieChart,
      color: 'red',
      type: 'image'
    },
    {
      id: 'category_performance',
      name: 'Category Performance',
      description: 'Performance analysis by security category',
      icon: BarChart3,
      color: 'purple',
      type: 'image'
    }
  ];

  const colorClasses = {
    blue: {
      bg: 'bg-blue-50',
      border: 'border-blue-200',
      text: 'text-blue-800',
      button: 'bg-blue-600 hover:bg-blue-700'
    },
    green: {
      bg: 'bg-green-50',
      border: 'border-green-200',
      text: 'text-green-800',
      button: 'bg-green-600 hover:bg-green-700'
    },
    orange: {
      bg: 'bg-orange-50',
      border: 'border-orange-200',
      text: 'text-orange-800',
      button: 'bg-orange-600 hover:bg-orange-700'
    },
    red: {
      bg: 'bg-red-50',
      border: 'border-red-200',
      text: 'text-red-800',
      button: 'bg-red-600 hover:bg-red-700'
    },
    purple: {
      bg: 'bg-purple-50',
      border: 'border-purple-200',
      text: 'text-purple-800',
      button: 'bg-purple-600 hover:bg-purple-700'
    }
  };

  const generateAllVisualizations = async () => {
    try {
      setGenerating(true);
      setError(null);
      
      const response = await axios.get(`${API_BASE_URL}/api/visualizations/all`);
      setVisualizations(response.data.visualizations || {});
      
    } catch (err) {
      console.error('Failed to generate visualizations:', err);
      setError('Failed to generate visualizations. Please ensure a scan has been completed.');
    } finally {
      setGenerating(false);
    }
  };

  const viewVisualization = async (vizType) => {
    try {
      setLoading(true);
      setError(null);
      
      const viz = vizTypes.find(v => v.id === vizType);
      
      if (viz.type === 'html') {
        // Open dashboard in new window
        window.open(`${API_BASE_URL}/api/visualizations/${vizType}`, '_blank');
      } else {
        // Display image inline
        setSelectedViz({
          type: vizType,
          url: `${API_BASE_URL}/api/visualizations/${vizType}?t=${Date.now()}`
        });
      }
      
    } catch (err) {
      console.error('Failed to load visualization:', err);
      setError(`Failed to load ${vizType}. Please try again.`);
    } finally {
      setLoading(false);
    }
  };

  const downloadVisualization = async (vizType) => {
    try {
      const viz = vizTypes.find(v => v.id === vizType);
      const extension = viz.type === 'html' ? 'html' : 'png';
      
      const response = await axios.get(
        `${API_BASE_URL}/api/visualizations/${vizType}`,
        { responseType: 'blob' }
      );
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${vizType}.${extension}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
    } catch (err) {
      console.error('Failed to download visualization:', err);
      alert('Failed to download visualization. Please try again.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-purple-600 to-pink-600 rounded-lg p-6 text-white">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold mb-2">Interactive Visualizations</h2>
            <p className="text-purple-100">
              Advanced charts and dashboards for compliance analysis
            </p>
          </div>
          <BarChart3 className="w-12 h-12 opacity-50" />
        </div>
      </div>

      {/* Generate All Button */}
      <div className="bg-white rounded-lg shadow-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold mb-1">Generate All Visualizations</h3>
            <p className="text-sm text-gray-600">
              Create all charts and dashboards at once for comprehensive analysis
            </p>
          </div>
          <button
            onClick={generateAllVisualizations}
            disabled={generating}
            className="px-6 py-3 bg-gradient-to-r from-purple-600 to-pink-600 text-white rounded-lg hover:from-purple-700 hover:to-pink-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center shadow-lg"
          >
            {generating ? (
              <>
                <Loader className="w-5 h-5 mr-2 animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <ImageIcon className="w-5 h-5 mr-2" />
                Generate All
              </>
            )}
          </button>
        </div>

        {Object.keys(visualizations).length > 0 && (
          <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-lg">
            <p className="text-sm text-green-800">
              ✅ Generated {Object.keys(visualizations).length} visualizations successfully!
            </p>
          </div>
        )}
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center">
            <AlertTriangle className="w-5 h-5 text-red-600 mr-3" />
            <p className="text-red-800 text-sm">{error}</p>
          </div>
        </div>
      )}

      {/* Visualization Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {vizTypes.map((viz, index) => {
          const colors = colorClasses[viz.color];
          const Icon = viz.icon;
          
          return (
            <motion.div
              key={viz.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className={`${colors.bg} border-2 ${colors.border} rounded-lg p-6 hover:shadow-xl transition-all`}
            >
              <div className="flex items-start justify-between mb-4">
                <div className={`p-3 ${colors.button} rounded-lg`}>
                  <Icon className="w-6 h-6 text-white" />
                </div>
                <span className={`text-xs px-2 py-1 ${colors.bg} ${colors.text} rounded-full font-semibold border ${colors.border}`}>
                  {viz.type.toUpperCase()}
                </span>
              </div>

              <h3 className={`text-lg font-bold ${colors.text} mb-2`}>
                {viz.name}
              </h3>
              <p className="text-gray-600 text-sm mb-4">
                {viz.description}
              </p>

              <div className="flex space-x-2">
                <button
                  onClick={() => viewVisualization(viz.id)}
                  disabled={loading}
                  className={`flex-1 px-4 py-2 ${colors.button} text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center text-sm`}
                >
                  {loading ? (
                    <Loader className="w-4 h-4 animate-spin" />
                  ) : (
                    <>
                      <ExternalLink className="w-4 h-4 mr-1" />
                      View
                    </>
                  )}
                </button>
                <button
                  onClick={() => downloadVisualization(viz.id)}
                  className={`px-4 py-2 ${colors.button} text-white rounded-lg transition-colors flex items-center justify-center text-sm`}
                >
                  <Download className="w-4 h-4" />
                </button>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Selected Visualization Display */}
      {selectedViz && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-white rounded-lg shadow-2xl p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">
              {vizTypes.find(v => v.id === selectedViz.type)?.name}
            </h3>
            <button
              onClick={() => setSelectedViz(null)}
              className="text-gray-500 hover:text-gray-700"
            >
              ✕
            </button>
          </div>
          <div className="bg-gray-50 rounded-lg p-4 flex items-center justify-center">
            <img
              src={selectedViz.url}
              alt={selectedViz.type}
              className="max-w-full h-auto rounded-lg shadow-lg"
              onError={(e) => {
                e.target.src = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300"><rect width="400" height="300" fill="%23f3f4f6"/><text x="50%" y="50%" text-anchor="middle" fill="%236b7280">Failed to load image</text></svg>';
              }}
            />
          </div>
        </motion.div>
      )}

      {/* Info Box */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
        <h4 className="font-semibold text-blue-900 mb-2">💡 Visualization Tips</h4>
        <ul className="text-sm text-blue-800 space-y-1">
          <li>• Interactive Dashboard opens in a new window with full interactivity</li>
          <li>• Image visualizations can be downloaded as PNG files</li>
          <li>• Generate all visualizations at once for comprehensive analysis</li>
          <li>• Visualizations are regenerated each time for latest data</li>
        </ul>
      </div>
    </div>
  );
};

export default VisualizationsPanel;

