import axios from 'axios';

// 创建axios实例
const api = axios.create({
  baseURL: 'http://localhost:8000/',
  timeout: 10000,
});

// 请求拦截器
api.interceptors.request.use(
  (config) => {
    // 在发送请求之前可以做一些处理
    return config;
  },
  (error) => {
    // 处理请求错误
    return Promise.reject(error);
  }
);

// 响应拦截器
api.interceptors.response.use(
  (response) => {
    // 处理响应数据
    return response.data;
  },
  (error) => {
    // 处理响应错误
    return Promise.reject(error);
  }
);

// 信息收集API
const infoCollectionAPI = {
  // 获取所有资产
  getAssets() {
    return api.get('data_collection/assets/');
  },

  // 获取资产详情
  getAssetDetail(id) {
    return api.get(`data_collection/assets/${id}/`);
  },

  // 获取扫描结果
  getScanResults(params) {
    return api.get('data_collection/scan-results/', { params });
  },

  // 获取被动扫描结果
  getPassiveScanResults(params) {
    return api.get('data_collection/scan-results/passive/', { params });
  },

  // 获取主动扫描结果
  getActiveScanResults(params) {
    return api.get('data_collection/scan-results/active/', { params });
  },

  // 删除扫描结果
  deleteScanResult(id) {
    return api.delete(`data_collection/scan-results/${id}/`);
  }
};

// 漏洞扫描API
const vulnScanAPI = {
  // 获取扫描结果
  getScanResults(params) {
    return api.get('vuln_scan/results/', { params });
  },

  // 获取被动扫描结果
  getPassiveScanResults(params) {
    return api.get('vuln_scan/results/passive/', { params });
  },

  // 获取主动扫描结果
  getActiveScanResults(params) {
    return api.get('vuln_scan/results/active/', { params });
  },

  // 删除扫描结果
  deleteScanResult(id) {
    return api.delete(`vuln_scan/results/${id}/`);
  }
};

// 规则管理API
const rulesAPI = {
  // 获取所有信息收集规则
  getInfoCollectionRules(params) {
    return api.get('rules/info-collection/', { params });
  },

  // 按模块获取信息收集规则
  getInfoCollectionRulesByModule(module, params) {
    return api.get(`rules/info-collection/module/${module}/`, { params });
  },

  // 按模块和扫描类型获取信息收集规则
  getInfoCollectionRulesByModuleAndType(module, scanType, params) {
    return api.get(`rules/info-collection/module/${module}/scan-type/${scanType}/`, { params });
  },

  // 创建信息收集规则
  createInfoCollectionRule(data) {
    return api.post('rules/info-collection/', data);
  },

  // 更新信息收集规则
  updateInfoCollectionRule(id, data) {
    return api.put(`rules/info-collection/${id}/`, data);
  },

  // 删除信息收集规则
  deleteInfoCollectionRule(id) {
    return api.delete(`rules/info-collection/${id}/`);
  },

  // 获取所有漏洞扫描规则
  getVulnScanRules(params) {
    return api.get('rules/vuln-scan/', { params });
  },

  // 按类型获取漏洞扫描规则
  getVulnScanRulesByType(vulnType, params) {
    return api.get(`rules/vuln-scan/type/${vulnType}/`, { params });
  },

  // 按类型和扫描类型获取漏洞扫描规则
  getVulnScanRulesByTypeAndScanType(vulnType, scanType, params) {
    return api.get(`rules/vuln-scan/type/${vulnType}/scan-type/${scanType}/`, { params });
  },

  // 创建漏洞扫描规则
  createVulnScanRule(data) {
    return api.post('rules/vuln-scan/', data);
  },

  // 更新漏洞扫描规则
  updateVulnScanRule(id, data) {
    return api.put(`rules/vuln-scan/${id}/`, data);
  },

  // 删除漏洞扫描规则
  deleteVulnScanRule(id) {
    return api.delete(`rules/vuln-scan/${id}/`);
  }
};

// 系统设置API
const settingsAPI = {
  // 获取系统设置
  getSettings() {
    return api.get('data_collection/settings/');
  },

  // 更新系统设置
  updateSettings(data) {
    return api.put('data_collection/settings/', data);
  },

  // 获取跳过目标列表
  getSkipTargets() {
    return api.get('data_collection/skip-targets/');
  },

  // 创建跳过目标
  createSkipTarget(data) {
    return api.post('data_collection/skip-targets/', data);
  },

  // 删除跳过目标
  deleteSkipTarget(id) {
    return api.delete(`data_collection/skip-targets/${id}/`);
  }
};

export {
  infoCollectionAPI,
  vulnScanAPI,
  rulesAPI,
  settingsAPI
};