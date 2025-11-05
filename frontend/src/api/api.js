import axios from 'axios';

// Base API URL - Change this to your backend URL
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

// Create axios instance with default config
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for adding auth tokens if needed
apiClient.interceptors.request.use(
  (config) => {
    // Add auth token if available
    // const token = localStorage.getItem('token');
    // if (token) {
    //   config.headers.Authorization = `Bearer ${token}`;
    // }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

// ============= API ENDPOINTS =============

// Compliance Data
export const getComplianceSummary = async () => {
  try {
    const response = await apiClient.get('/api/compliance/summary');
    return response.data;
  } catch (error) {
    console.error('Error fetching compliance summary:', error);
    throw error;
  }
};

export const getComplianceReport = async () => {
  try {
    const response = await apiClient.get('/api/compliance/report');
    return response.data;
  } catch (error) {
    console.error('Error fetching compliance report:', error);
    throw error;
  }
};

export const getComplianceRemediation = async () => {
  try {
    const response = await apiClient.get('/api/compliance/remediation');
    return response.data;
  } catch (error) {
    console.error('Error fetching remediation data:', error);
    throw error;
  }
};

// Training & Collection
export const trainModel = async (data) => {
  try {
    const response = await apiClient.post('/api/compliance/train', data);
    return response.data;
  } catch (error) {
    console.error('Error training model:', error);
    throw error;
  }
};

export const collectData = async (data) => {
  try {
    const response = await apiClient.post('/api/compliance/collect', data);
    return response.data;
  } catch (error) {
    console.error('Error collecting data:', error);
    throw error;
  }
};

// Inference
export const runInference = async (data) => {
  try {
    const response = await apiClient.post('/api/compliance/infer', data);
    return response.data;
  } catch (error) {
    console.error('Error running inference:', error);
    throw error;
  }
};

// Audit
export const getAuditReport = async () => {
  try {
    const response = await apiClient.get('/api/audit/report');
    return response.data;
  } catch (error) {
    console.error('Error fetching audit report:', error);
    throw error;
  }
};

export const getAuditRemediation = async () => {
  try {
    const response = await apiClient.get('/api/audit/remediation');
    return response.data;
  } catch (error) {
    console.error('Error fetching audit remediation:', error);
    throw error;
  }
};

// Reports
export const generateReport = async (filters) => {
  try {
    const response = await apiClient.post('/api/reports/generate', filters);
    return response.data;
  } catch (error) {
    console.error('Error generating report:', error);
    throw error;
  }
};

export const downloadReportPDF = async (reportId) => {
  try {
    const response = await apiClient.get(`/api/reports/${reportId}/download/pdf`, {
      responseType: 'blob',
    });
    
    // Create download link
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `compliance_report_${reportId}.pdf`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    
    return true;
  } catch (error) {
    console.error('Error downloading PDF:', error);
    throw error;
  }
};

export const downloadReportExcel = async (reportId) => {
  try {
    const response = await apiClient.get(`/api/reports/${reportId}/download/excel`, {
      responseType: 'blob',
    });
    
    // Create download link
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `compliance_report_${reportId}.xlsx`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    
    return true;
  } catch (error) {
    console.error('Error downloading Excel:', error);
    throw error;
  }
};

export const downloadRemediationScript = async (reportId) => {
  try {
    const response = await apiClient.get(`/api/reports/${reportId}/remediation`, {
      responseType: 'blob',
    });
    
    // Create download link
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `remediation_script_${reportId}.sh`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    
    return true;
  } catch (error) {
    console.error('Error downloading remediation script:', error);
    throw error;
  }
};

export default apiClient;