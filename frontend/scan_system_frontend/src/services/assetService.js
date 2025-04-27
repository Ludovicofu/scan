// src/services/assetService.js
// 资产管理服务 - 处理资产相关的业务逻辑

import { assetAPI } from '@/services/api';

export default {
  /**
   * 获取资产列表
   * @param {Object} params 查询参数
   * @returns {Promise} 资产列表数据
   */
  async getAssets(params = {}) {
    try {
      return await assetAPI.getAssets(params);
    } catch (error) {
      console.error('获取资产列表失败', error);
      throw error;
    }
  },

  /**
   * 获取资产详情
   * @param {Number} id 资产ID
   * @returns {Promise} 资产详情数据
   */
  async getAssetDetail(id) {
    try {
      return await assetAPI.getAssetDetail(id);
    } catch (error) {
      console.error('获取资产详情失败', error);
      throw error;
    }
  },

  /**
   * 删除资产
   * @param {Number} id 资产ID
   * @returns {Promise} 删除结果
   */
  async deleteAsset(id) {
    try {
      return await assetAPI.deleteAsset(id);
    } catch (error) {
      console.error('删除资产失败', error);
      throw error;
    }
  },

  /**
   * 获取资产的信息收集结果
   * @param {Number} assetId 资产ID
   * @param {Object} params 查询参数
   * @returns {Promise} 信息收集结果数据
   */
  async getAssetInfoResults(assetId, params = {}) {
    try {
      return await assetAPI.getAssetInfoResults(assetId, params);
    } catch (error) {
      console.error('获取资产信息收集结果失败', error);
      throw error;
    }
  },

  /**
   * 获取资产的漏洞检测结果
   * @param {Number} assetId 资产ID
   * @param {Object} params 查询参数
   * @returns {Promise} 漏洞检测结果数据
   */
  async getAssetVulnResults(assetId, params = {}) {
    try {
      return await assetAPI.getAssetVulnResults(assetId, params);
    } catch (error) {
      console.error('获取资产漏洞检测结果失败', error);
      throw error;
    }
  },

  /**
   * 计算资产统计数据
   * @param {Array} assets 资产列表
   * @returns {Object} 统计数据
   */
  getAssetStats(assets) {
    if (!assets || !Array.isArray(assets)) {
      return {
        totalAssets: 0,
        totalInfoResults: 0,
        totalVulnResults: 0,
        highVulnAssets: 0
      };
    }

    // 计算统计数据
    const totalAssets = assets.length;
    const totalInfoResults = assets.reduce((sum, asset) => sum + (asset.info_results_count || 0), 0);
    const totalVulnResults = assets.reduce((sum, asset) => sum + (asset.vuln_results_count || 0), 0);

    // 计算有高危漏洞的资产数量 (如果有这个数据的话)
    const highVulnAssets = assets.filter(asset => asset.high_vuln_count > 0).length;

    return {
      totalAssets,
      totalInfoResults,
      totalVulnResults,
      highVulnAssets
    };
  }
};