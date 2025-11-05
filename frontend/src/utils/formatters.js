/**
 * Utility functions for formatting data in the Compliance AI dashboard
 */

/**
 * Format a number as percentage
 * @param {number} value - Number to format (0-100)
 * @param {number} decimals - Number of decimal places
 * @returns {string} Formatted percentage
 */
export const formatPercentage = (value, decimals = 1) => {
    return `${value.toFixed(decimals)}%`;
  };
  
  /**
   * Format a date string
   * @param {string|Date} date - Date to format
   * @returns {string} Formatted date
   */
  export const formatDate = (date) => {
    const d = new Date(date);
    return d.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };
  
  /**
   * Format a date with time
   * @param {string|Date} date - Date to format
   * @returns {string} Formatted date and time
   */
  export const formatDateTime = (date) => {
    const d = new Date(date);
    return d.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };
  
  /**
   * Get color based on compliance score
   * @param {number} score - Compliance score (0-100)
   * @returns {string} Color hex code
   */
  export const getScoreColor = (score) => {
    if (score >= 90) return '#00ff88';  // Green - Excellent
    if (score >= 75) return '#00d9ff';  // Cyan - Good
    if (score >= 60) return '#ff9800';  // Orange - Warning
    return '#ff4444';                    // Red - Critical
  };
  
  /**
   * Get risk level based on score
   * @param {number} score - Compliance score (0-100)
   * @returns {string} Risk level
   */
  export const getRiskLevel = (score) => {
    if (score >= 90) return 'Low';
    if (score >= 75) return 'Medium';
    if (score >= 60) return 'High';
    return 'Critical';
  };
  
  /**
   * Get severity color
   * @param {string} severity - Severity level
   * @returns {string} Color hex code
   */
  export const getSeverityColor = (severity) => {
    const colors = {
      'Critical': '#ff4444',
      'High': '#ff9800',
      'Medium': '#ffeb3b',
      'Low': '#00ff88'
    };
    return colors[severity] || '#ffffff';
  };
  
  /**
   * Format large numbers with commas
   * @param {number} num - Number to format
   * @returns {string} Formatted number
   */
  export const formatNumber = (num) => {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  };
  
  /**
   * Calculate trend percentage
   * @param {number} current - Current value
   * @param {number} previous - Previous value
   * @returns {number} Trend percentage
   */
  export const calculateTrend = (current, previous) => {
    if (previous === 0) return 0;
    return ((current - previous) / previous) * 100;
  };
  
  /**
   * Format framework name
   * @param {string} framework - Framework identifier
   * @returns {string} Formatted framework name
   */
  export const formatFramework = (framework) => {
    const frameworks = {
      'iso27001': 'ISO 27001',
      'rbi': 'RBI Cyber Security',
      'cis': 'CIS Controls',
      'nist': 'NIST Framework',
      'pci': 'PCI DSS',
      'hipaa': 'HIPAA',
      'gdpr': 'GDPR'
    };
    return frameworks[framework.toLowerCase()] || framework;
  };
  
  /**
   * Truncate text to specified length
   * @param {string} text - Text to truncate
   * @param {number} length - Maximum length
   * @returns {string} Truncated text
   */
  export const truncateText = (text, length = 50) => {
    if (text.length <= length) return text;
    return text.substring(0, length) + '...';
  };
  
  /**
   * Get status badge info
   * @param {string} status - Status type
   * @returns {Object} Badge configuration
   */
  export const getStatusBadge = (status) => {
    const badges = {
      'Compliant': {
        color: '#00ff88',
        background: 'rgba(0, 255, 136, 0.2)',
        label: 'Compliant'
      },
      'Partial': {
        color: '#ff9800',
        background: 'rgba(255, 152, 0, 0.2)',
        label: 'Partial'
      },
      'Non-Compliant': {
        color: '#ff4444',
        background: 'rgba(255, 68, 68, 0.2)',
        label: 'Non-Compliant'
      },
      'Pending': {
        color: '#00d9ff',
        background: 'rgba(0, 217, 255, 0.2)',
        label: 'Pending'
      }
    };
    return badges[status] || badges['Pending'];
  };
  
  /**
   * Sort data by property
   * @param {Array} data - Array to sort
   * @param {string} property - Property to sort by
   * @param {string} order - Sort order ('asc' or 'desc')
   * @returns {Array} Sorted array
   */
  export const sortData = (data, property, order = 'asc') => {
    return [...data].sort((a, b) => {
      const aVal = a[property];
      const bVal = b[property];
      
      if (order === 'asc') {
        return aVal > bVal ? 1 : -1;
      } else {
        return aVal < bVal ? 1 : -1;
      }
    });
  };
  
  /**
   * Filter data by search term
   * @param {Array} data - Array to filter
   * @param {string} searchTerm - Search term
   * @param {Array} searchFields - Fields to search in
   * @returns {Array} Filtered array
   */
  export const filterData = (data, searchTerm, searchFields = []) => {
    if (!searchTerm) return data;
    
    const term = searchTerm.toLowerCase();
    
    return data.filter(item => {
      return searchFields.some(field => {
        const value = item[field];
        return value && value.toString().toLowerCase().includes(term);
      });
    });
  };
  
  /**
   * Group data by property
   * @param {Array} data - Array to group
   * @param {string} property - Property to group by
   * @returns {Object} Grouped data
   */
  export const groupData = (data, property) => {
    return data.reduce((groups, item) => {
      const key = item[property];
      if (!groups[key]) {
        groups[key] = [];
      }
      groups[key].push(item);
      return groups;
    }, {});
  };
  
  /**
   * Calculate compliance percentage
   * @param {number} compliant - Number of compliant controls
   * @param {number} total - Total number of controls
   * @returns {number} Compliance percentage
   */
  export const calculateCompliancePercentage = (compliant, total) => {
    if (total === 0) return 0;
    return (compliant / total) * 100;
  };
  
  /**
   * Get time ago from date
   * @param {string|Date} date - Date to compare
   * @returns {string} Time ago string
   */
  export const getTimeAgo = (date) => {
    const now = new Date();
    const past = new Date(date);
    const diffMs = now - past;
    
    const diffSeconds = Math.floor(diffMs / 1000);
    const diffMinutes = Math.floor(diffSeconds / 60);
    const diffHours = Math.floor(diffMinutes / 60);
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffDays > 30) return formatDate(date);
    if (diffDays > 0) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    if (diffHours > 0) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    if (diffMinutes > 0) return `${diffMinutes} minute${diffMinutes > 1 ? 's' : ''} ago`;
    return 'Just now';
  };
  
  export default {
    formatPercentage,
    formatDate,
    formatDateTime,
    getScoreColor,
    getRiskLevel,
    getSeverityColor,
    formatNumber,
    calculateTrend,
    formatFramework,
    truncateText,
    getStatusBadge,
    sortData,
    filterData,
    groupData,
    calculateCompliancePercentage,
    getTimeAgo
  };