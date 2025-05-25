// 报告管理服务 - 处理报告相关的业务逻辑

import { reportAPI } from '@/services/api';

export default {
  /**
   * 获取报告模板列表
   * @param {Object} params 查询参数
   * @returns {Promise} 报告模板列表数据
   */
  async getTemplates(params = {}) {
    try {
      return await reportAPI.getTemplates(params);
    } catch (error) {
      console.error('获取报告模板列表失败', error);
      throw error;
    }
  },

  /**
   * 上传报告模板
   * @param {FormData} formData 表单数据
   * @returns {Promise} 上传结果
   */
  async uploadTemplate(formData) {
    try {
      return await reportAPI.uploadTemplate(formData);
    } catch (error) {
      console.error('上传报告模板失败', error);
      throw error;
    }
  },

  /**
   * 删除报告模板
   * @param {Number} id 模板ID
   * @returns {Promise} 删除结果
   */
  async deleteTemplate(id) {
    try {
      return await reportAPI.deleteTemplate(id);
    } catch (error) {
      console.error('删除报告模板失败', error);
      throw error;
    }
  },

  /**
   * 获取报告列表
   * @param {Object} params 查询参数
   * @returns {Promise} 报告列表数据
   */
  async getReports(params = {}) {
    try {
      return await reportAPI.getReports(params);
    } catch (error) {
      console.error('获取报告列表失败', error);
      throw error;
    }
  },

  /**
   * 获取报告详情
   * @param {Number} id 报告ID
   * @returns {Promise} 报告详情数据
   */
  async getReportDetail(id) {
    try {
      return await reportAPI.getReportDetail(id);
    } catch (error) {
      console.error('获取报告详情失败', error);
      throw error;
    }
  },

  /**
   * 生成报告
   * @param {Object} data 报告数据
   * @returns {Promise} 生成结果
   */
  async generateReport(data) {
    try {
      return await reportAPI.generateReport(data);
    } catch (error) {
      console.error('生成报告失败', error);
      throw error;
    }
  },

  /**
   * 下载报告
   * @param {Number} id 报告ID
   * @returns {Promise} 下载结果
   */
  async downloadReport(id) {
    try {
      const response = await reportAPI.downloadReport(id);

      // 从Content-Disposition中提取文件名
      const contentDisposition = response.headers['content-disposition'];
      let fileName = 'report.pdf'; // 默认文件名

      if (contentDisposition) {
        const fileNameMatch = contentDisposition.match(/filename="(.+)"/);
        if (fileNameMatch && fileNameMatch[1]) {
          fileName = fileNameMatch[1];
        }
      }

      // 创建Blob对象
      const blob = new Blob([response.data], { type: response.headers['content-type'] });

      // 创建下载链接
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', fileName);
      document.body.appendChild(link);

      // 模拟点击下载
      link.click();

      // 清理
      window.URL.revokeObjectURL(url);
      document.body.removeChild(link);

      return { status: 'success', message: '报告下载成功' };
    } catch (error) {
      console.error('下载报告失败', error);
      throw error;
    }
  },

  /**
   * 删除报告
   * @param {Number} id 报告ID
   * @returns {Promise} 删除结果
   */
  async deleteReport(id) {
    try {
      return await reportAPI.deleteReport(id);
    } catch (error) {
      console.error('删除报告失败', error);
      throw error;
    }
  },

  /**
   * 获取报告状态显示文本
   * @param {String} status 状态代码
   * @returns {String} 状态显示文本
   */
  getStatusText(status) {
    const statusMap = {
      'generating': '生成中',
      'completed': '已完成',
      'failed': '失败'
    };
    return statusMap[status] || '未知状态';
  },

  /**
   * 获取报告类型显示文本
   * @param {String} reportType 报告类型代码
   * @returns {String} 类型显示文本
   */
  getTypeText(reportType) {
    const typeMap = {
      'asset': '资产报告',
      'vuln': '漏洞报告',
      'comprehensive': '综合报告'
    };
    return typeMap[reportType] || '未知类型';
  },

  /**
   * 获取报告类型标签样式
   * @param {String} reportType 报告类型代码
   * @returns {String} 标签类型
   */
  getTypeTagType(reportType) {
    const typeMap = {
      'asset': 'info',
      'vuln': 'danger',
      'comprehensive': 'success'
    };
    return typeMap[reportType] || 'info';
  },

  /**
   * 获取报告状态标签样式
   * @param {String} status 状态代码
   * @returns {String} 标签类型
   */
  getStatusTagType(status) {
    const statusMap = {
      'generating': 'warning',
      'completed': 'success',
      'failed': 'danger'
    };
    return statusMap[status] || 'info';
  }
};