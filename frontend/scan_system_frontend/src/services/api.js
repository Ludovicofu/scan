/* eslint-disable no-unused-vars */
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

// 响应拦截器增强版
api.interceptors.response.use(
  (response) => {
    // 处理响应数据
    console.log("API响应成功:", response.config.url, response.data);
    return response.data;
  },
  (error) => {
    // 增强错误日志
    console.error('API请求错误:', error);
    if (error.response) {
      console.error('错误状态码:', error.response.status);
      console.error('错误数据:', error.response.data);
    } else if (error.request) {
      console.error('未收到响应，请求信息:', error.request);
    } else {
      console.error('请求配置出错:', error.message);
    }
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
    getVulnScanRules(params) {
      return api.get('rules/vuln-scan/', { params });
    },

    // 按类型获取漏洞扫描规则
    getVulnScanRulesByType(vulnType, params) {
      return api.get(`rules/vuln-scan/type/${vulnType}/`, { params });
    },

    // 创建漏洞扫描规则 - 移除scan_type参数
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
    },

    // 获取漏洞扫描结果
    getScanResults(params) {
      return api.get('vuln_scan/results/', { params });
    },

    // 按类型获取漏洞扫描结果
    getVulnResultsByType(vulnType, params) {
      return api.get(`vuln_scan/results/type/${vulnType}/`, { params });
    },

    // 获取漏洞扫描结果详情
    getScanResultDetail(id) {
      return api.get(`vuln_scan/results/${id}/`);
    },

    // 删除漏洞扫描结果
    deleteScanResult(id) {
      return api.delete(`vuln_scan/results/${id}/`);
    },

    // 验证漏洞
    verifyVulnerability(id) {
      return api.post(`vuln_scan/results/${id}/verify/`);
    }
};
// 规则管理API
const rulesAPI = {
  // 获取所有信息收集规则
  getInfoCollectionRules(params) {
    console.log("调用 getInfoCollectionRules, 参数:", params);
    return api.get('rules/info-collection/', { params })
      .then(response => {
        console.log("获取所有规则成功:", response);
        return response;
      })
      .catch(error => {
        console.error("获取所有规则失败:", error);
        throw error;
      });
  },

  // 按模块获取信息收集规则
  getInfoCollectionRulesByModule(module, params) {
    console.log("调用 getInfoCollectionRulesByModule, 模块:", module, "参数:", params);
    return api.get(`rules/info-collection/module/${module}/`, { params })
      .then(response => {
        console.log("获取模块规则成功:", response);
        return response;
      })
      .catch(error => {
        console.error(`获取模块[${module}]规则失败:`, error);
        throw error;
      });
  },

  // 按模块和扫描类型获取信息收集规则
  getInfoCollectionRulesByModuleAndType(module, scanType, params) {
    console.log("调用 getInfoCollectionRulesByModuleAndType, 模块:", module, "类型:", scanType, "参数:", params);
    return api.get(`rules/info-collection/module/${module}/scan-type/${scanType}/`, { params })
      .then(response => {
        console.log("获取模块和类型规则成功:", response);
        return response;
      })
      .catch(error => {
        console.error(`获取模块[${module}]类型[${scanType}]规则失败:`, error);
        throw error;
      });
  },

  // 创建信息收集规则
  createInfoCollectionRule(data) {
    console.log("创建规则数据:", data);
    return api.post('rules/info-collection/', data)
      .then(response => {
        console.log("创建规则成功:", response);
        return response;
      })
      .catch(error => {
        console.error("创建规则失败:", error);
        throw error;
      });
  },

  // 更新信息收集规则
  updateInfoCollectionRule(id, data) {
    console.log("更新规则, ID:", id, "数据:", data);
    return api.put(`rules/info-collection/${id}/`, data)
      .then(response => {
        console.log("更新规则成功:", response);
        return response;
      })
      .catch(error => {
        console.error(`更新规则[${id}]失败:`, error);
        throw error;
      });
  },

  // 删除信息收集规则
  deleteInfoCollectionRule(id) {
    return api.delete(`rules/info-collection/${id}/`)
      .then(response => {
        console.log(`删除规则[${id}]成功:`, response);
        return response;
      })
      .catch(error => {
        console.error(`删除规则[${id}]失败:`, error);
        throw error;
      });
  },

 // 获取所有漏洞扫描规则
  getVulnScanRules(params) {
    return api.get('rules/vuln-scan/', { params });
  },

  // 按类型获取漏洞扫描规则
  getVulnScanRulesByType(vulnType, params) {
    return api.get(`rules/vuln-scan/type/${vulnType}/`, { params });
  },

  // 创建漏洞扫描规则 - 移除scan_type参数
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

// 资产管理API
const assetAPI = {
  // 获取资产列表
  getAssets(params) {
    return api.get('asset_management/assets/', { params });
  },

  // 获取资产详情
  getAssetDetail(id) {
    return api.get(`asset_management/assets/${id}/`);
  },

  // 删除资产
  deleteAsset(id) {
    return api.delete(`asset_management/assets/${id}/`);
  },

  // 获取资产的信息收集结果
  getAssetInfoResults(assetId, params) {
    return api.get(`asset_management/assets/${assetId}/info-results/`, { params });
  },

  // 获取资产的漏洞检测结果
  getAssetVulnResults(assetId, params) {
    return api.get(`asset_management/assets/${assetId}/vuln-results/`, { params });
  },

  // 获取资产备注
  getAssetNotes(assetId, params) {
    return api.get(`asset_management/assets/${assetId}/notes/`, { params });
  },

  // 创建资产备注
  createAssetNote(assetId, data) {
    return api.post(`asset_management/assets/${assetId}/notes/`, data);
  },

  // 更新资产备注
  updateAssetNote(noteId, data) {
    return api.put(`asset_management/notes/${noteId}/`, data);
  },

  // 删除资产备注
  deleteAssetNote(noteId) {
    return api.delete(`asset_management/notes/${noteId}/`);
  },

  // 获取资产标签
  getTags(params) {
    return api.get('asset_management/tags/', { params });
  },

  // 获取资产分组
  getGroups(params) {
    return api.get('asset_management/groups/', { params });
  },

  // 获取资产统计信息
  getAssetStatistics() {
    return api.get('asset_management/statistics/');
  }
};


// 导出所有API服务
export {
  infoCollectionAPI,
  vulnScanAPI,
  rulesAPI,
  settingsAPI,
  assetAPI
};