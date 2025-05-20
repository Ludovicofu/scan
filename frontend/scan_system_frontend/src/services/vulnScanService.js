// src/services/vulnScanService.js - 新增服务文件
import { vulnScanAPI } from '@/services/api';
import { vulnScanWS } from '@/services/websocket';
import { ElNotification } from 'element-plus';

class VulnScanService {
  constructor() {
    // WebSocket连接状态
    this.isConnected = false;

    // 监听器
    this.listeners = {
      'result': [],
      'progress': [],
      'connection': [],
      'error': []
    };

    // 结果缓存
    this.resultCache = new Map(); // 以ID为键的完整结果缓存
    this.notifiedResults = new Set(); // 已通知过的结果标识符

    // 统计数据
    this.stats = {
      resultsReceived: 0,
      progressUpdates: 0,
      lastResultTime: null,
      lastProgressTime: null,
      connectionAttempts: 0
    };

    // 连接状态监控
    this.connectionMonitorInterval = null;
    this.reconnectTimer = null;

    // 自动加载缓存
    this._loadCacheFromStorage();
  }

  /**
   * 初始化服务并连接WebSocket
   */
  init() {
    console.log("初始化漏洞扫描服务...");

    // 如果已经是连接状态，先断开
    if (this.isConnected) {
      this.disconnect();
    }

    // 添加WebSocket事件监听
    this._setupWebSocketListeners();

    // 连接WebSocket
    this.connect();

    // 开始连接监控
    this._startConnectionMonitor();

    // 返回this以支持链式调用
    return this;
  }

  /**
   * 连接WebSocket
   * @returns {Promise} 连接Promise
   */
  connect() {
    this.stats.connectionAttempts++;

    return vulnScanWS.connect('ws://localhost:8000/ws/vuln_scan/')
      .then(() => {
        console.log("漏洞扫描WebSocket连接成功!");
        this.isConnected = true;
        this._notifyListeners('connection', { connected: true });
        return true;
      })
      .catch(error => {
        console.error("漏洞扫描WebSocket连接失败:", error);
        this.isConnected = false;
        this._notifyListeners('error', { error, type: 'connection' });
        this._notifyListeners('connection', { connected: false, error });
        return false;
      });
  }

  /**
   * 断开WebSocket连接
   */
  disconnect() {
    vulnScanWS.disconnect();
    this.isConnected = false;

    // 停止连接监控
    this._stopConnectionMonitor();

    // 移除WebSocket事件监听
    vulnScanWS.removeListener('scan_result', this._handleScanResult);
    vulnScanWS.removeListener('scan_progress', this._handleScanProgress);

    // 通知连接状态变更
    this._notifyListeners('connection', { connected: false });
  }

  /**
   * 重新连接WebSocket
   * @returns {Promise} 连接Promise
   */
  reconnect() {
    this.disconnect();
    return this.connect();
  }

  /**
   * 获取漏洞扫描结果
   * @param {string} vulnType 漏洞类型
   * @param {Object} params 查询参数
   * @returns {Promise} API响应Promise
   */
  async getVulnResults(vulnType, params = {}) {
    try {
      const response = await vulnScanAPI.getVulnResultsByType(vulnType, params);

      // 更新缓存
      if (response && response.results) {
        response.results.forEach(result => {
          // 将结果添加到缓存
          this.resultCache.set(result.id, result);

          // 标记为已通知
          this._markAsNotified(result);
        });

        // 保存缓存
        this._saveCacheToStorage();
      }

      return response;
    } catch (error) {
      console.error(`获取${vulnType}漏洞结果失败:`, error);
      this._notifyListeners('error', { error, type: 'api', method: 'getVulnResults' });
      throw error;
    }
  }

  /**
   * 删除漏洞扫描结果
   * @param {number} id 结果ID
   * @returns {Promise} API响应Promise
   */
  async deleteVulnResult(id) {
    try {
      const response = await vulnScanAPI.deleteScanResult(id);

      // 从缓存中移除
      this.resultCache.delete(id);

      // 保存缓存
      this._saveCacheToStorage();

      return response;
    } catch (error) {
      console.error(`删除漏洞结果${id}失败:`, error);
      this._notifyListeners('error', { error, type: 'api', method: 'deleteVulnResult' });
      throw error;
    }
  }

  /**
   * 验证漏洞
   * @param {number} id 结果ID
   * @returns {Promise} API响应Promise
   */
  async verifyVulnerability(id) {
    try {
      const response = await vulnScanAPI.verifyVulnerability(id);

      // 更新缓存中的数据
      if (this.resultCache.has(id)) {
        const result = this.resultCache.get(id);
        result.is_verified = true;
        this.resultCache.set(id, result);

        // 保存缓存
        this._saveCacheToStorage();
      }

      return response;
    } catch (error) {
      console.error(`验证漏洞${id}失败:`, error);
      this._notifyListeners('error', { error, type: 'api', method: 'verifyVulnerability' });
      throw error;
    }
  }

  /**
   * 添加事件监听器
   * @param {string} eventType 事件类型: 'result', 'progress', 'connection', 'error'
   * @param {function} callback 回调函数
   */
  addEventListener(eventType, callback) {
    if (this.listeners[eventType]) {
      // 检查是否已存在相同的回调
      if (!this.listeners[eventType].includes(callback)) {
        this.listeners[eventType].push(callback);
        console.log(`添加了${eventType}事件监听器，当前有${this.listeners[eventType].length}个`);
      }
    } else {
      console.warn(`不支持的事件类型: ${eventType}`);
    }
  }

  /**
   * 移除事件监听器
   * @param {string} eventType 事件类型
   * @param {function} callback 回调函数
   */
  removeEventListener(eventType, callback) {
    if (this.listeners[eventType]) {
      const index = this.listeners[eventType].indexOf(callback);
      if (index !== -1) {
        this.listeners[eventType].splice(index, 1);
        console.log(`移除了${eventType}事件监听器，剩余${this.listeners[eventType].length}个`);
      }
    }
  }

  /**
   * 获取WebSocket连接状态
   * @returns {boolean} 是否连接
   */
  getConnectionStatus() {
    // 同时检查本地状态和WebSocket状态
    const wsConnected = vulnScanWS.isConnected;

    // 如果状态不一致，更新本地状态
    if (this.isConnected !== wsConnected) {
      this.isConnected = wsConnected;

      // 通知连接状态变更
      this._notifyListeners('connection', { connected: this.isConnected });
    }

    return this.isConnected;
  }

  /**
   * 获取统计数据
   * @returns {Object} 统计数据
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * 获取缓存的结果
   * @param {string} vulnType 漏洞类型，不指定则返回所有
   * @returns {Array} 结果数组
   */
  getCachedResults(vulnType) {
    const results = Array.from(this.resultCache.values());

    if (vulnType) {
      return results.filter(result => result.vuln_type === vulnType);
    }

    return results;
  }

  /**
   * 清除结果缓存
   */
  clearCache() {
    this.resultCache.clear();
    this.notifiedResults.clear();
    this._saveCacheToStorage();
  }

  /**
   * 获取漏洞类型显示名称
   * @param {string} vulnType 漏洞类型
   * @returns {string} 显示名称
   */
  getVulnTypeDisplay(vulnType) {
    const vulnTypeMap = {
      'sql_injection': 'SQL注入',
      'xss': 'XSS跨站脚本',
      'file_inclusion': '文件包含',
      'command_injection': '命令执行',
      'ssrf': 'SSRF服务器端请求伪造'
    };
    return vulnTypeMap[vulnType] || vulnType;
  }

  /**
   * 根据严重性获取通知类型
   * @param {string} severity 严重性
   * @returns {string} 通知类型
   */
  getNotificationTypeFromSeverity(severity) {
    switch(severity) {
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'success';
    }
  }

  /**
   * 显示漏洞通知
   * @param {Object} result 漏洞结果
   */
  showNotification(result) {
    // 检查是否已通知
    if (this._isAlreadyNotified(result)) {
      return;
    }

    // 标记为已通知
    this._markAsNotified(result);

    // 构造通知内容
    const title = `发现${this.getVulnTypeDisplay(result.vuln_type)}漏洞`;
    let message = `${result.name}`;

    // 对于不同漏洞类型可以定制消息
    if (result.parameter) {
      message += ` (参数: ${result.parameter})`;
    }

    // 显示通知
    ElNotification({
      title: title,
      message: message,
      type: this.getNotificationTypeFromSeverity(result.severity),
      duration: 5000
    });
  }

  // 私有方法

  /**
   * 设置WebSocket监听器
   * @private
   */
  _setupWebSocketListeners() {
    // 绑定方法到this，避免上下文问题
    this._handleScanResult = this._handleScanResult.bind(this);
    this._handleScanProgress = this._handleScanProgress.bind(this);

    // 添加事件监听器
    vulnScanWS.addListener('scan_result', this._handleScanResult);
    vulnScanWS.addListener('scan_progress', this._handleScanProgress);

    // 添加连接状态监听
    vulnScanWS.addConnectionListener((connected) => {
      this.isConnected = connected;
      this._notifyListeners('connection', { connected });
    });

    // 添加错误监听
    vulnScanWS.addErrorListener((error) => {
      this._notifyListeners('error', { error, type: 'websocket' });
    });
  }

  /**
   * 处理扫描结果
   * @param {Object} message WebSocket消息
   * @private
   */
  _handleScanResult(message) {
    try {
      if (!message || !message.data) {
        console.warn('收到无效的扫描结果消息');
        return;
      }

      const result = message.data;
      console.log('收到漏洞扫描结果:', result);

      // 更新统计信息
      this.stats.resultsReceived++;
      this.stats.lastResultTime = new Date().toISOString();

      // 检查是否已处理过此结果
      if (this._isAlreadyNotified(result)) {
        console.log('跳过已通知的结果:', result.id);
        return;
      }

      // 保存结果到缓存
      this.resultCache.set(result.id, result);

      // 通知监听器
      this._notifyListeners('result', { result });

      // 保存缓存
      this._saveCacheToStorage();

    } catch (error) {
      console.error('处理扫描结果消息时出错:', error);
      this._notifyListeners('error', { error, type: 'handler', handler: 'result' });
    }
  }

  /**
   * 处理扫描进度
   * @param {Object} message WebSocket消息
   * @private
   */
  _handleScanProgress(message) {
    try {
      if (!message || !message.data) {
        return;
      }

      const progressData = message.data;
      console.log('扫描进度更新:', progressData);

      // 更新统计信息
      this.stats.progressUpdates++;
      this.stats.lastProgressTime = new Date().toISOString();

      // 通知监听器
      this._notifyListeners('progress', { progress: progressData });

    } catch (error) {
      console.error('处理扫描进度消息时出错:', error);
      this._notifyListeners('error', { error, type: 'handler', handler: 'progress' });
    }
  }

  /**
   * 通知所有指定类型的监听器
   * @param {string} eventType 事件类型
   * @param {Object} data 事件数据
   * @private
   */
  _notifyListeners(eventType, data) {
    if (this.listeners[eventType]) {
      this.listeners[eventType].forEach(listener => {
        try {
          listener(data);
        } catch (error) {
          console.error(`执行${eventType}监听器时出错:`, error);
        }
      });
    }
  }

  /**
   * 开始连接监控
   * @private
   */
  _startConnectionMonitor() {
    // 清除可能已存在的监控
    this._stopConnectionMonitor();

    // 每30秒检查一次连接状态
    this.connectionMonitorInterval = setInterval(() => {
      this._checkConnection();
    }, 30000);
  }

  /**
   * 停止连接监控
   * @private
   */
  _stopConnectionMonitor() {
    if (this.connectionMonitorInterval) {
      clearInterval(this.connectionMonitorInterval);
      this.connectionMonitorInterval = null;
    }

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  /**
   * 检查连接状态
   * @private
   */
  _checkConnection() {
    // 获取当前实际连接状态
    const currentStatus = vulnScanWS.isConnected;

    // 如果状态不一致，更新状态并通知
    if (this.isConnected !== currentStatus) {
      this.isConnected = currentStatus;
      this._notifyListeners('connection', { connected: currentStatus });

      // 如果断开了，尝试重连
      if (!currentStatus) {
        console.log('检测到WebSocket连接已断开，计划重连');

        // 避免重复计时器
        if (this.reconnectTimer) {
          clearTimeout(this.reconnectTimer);
        }

        // 3秒后尝试重连
        this.reconnectTimer = setTimeout(() => {
          console.log('执行重连...');
          this.reconnect();
        }, 3000);
      }
    }

    return this.isConnected;
  }

  /**
   * 从localStorage加载缓存
   * @private
   */
  _loadCacheFromStorage() {
    try {
      // 加载已通知结果集
      const notifiedData = localStorage.getItem('vulnScanNotifiedResults');
      if (notifiedData) {
        this.notifiedResults = new Set(JSON.parse(notifiedData));
      }

      // 加载结果缓存
      const cacheData = localStorage.getItem('vulnScanResultCache');
      if (cacheData) {
        // Map需要特殊处理
        this.resultCache = new Map(JSON.parse(cacheData));
      }

      console.log(`缓存加载完成: ${this.notifiedResults.size}个已通知结果, ${this.resultCache.size}个结果缓存`);
    } catch (error) {
      console.error('从localStorage加载缓存失败:', error);
    }
  }

  /**
   * 将缓存保存到localStorage
   * @private
   */
  _saveCacheToStorage() {
    try {
      // 保存已通知结果集
      localStorage.setItem('vulnScanNotifiedResults', JSON.stringify(Array.from(this.notifiedResults)));

      // 保存结果缓存
      localStorage.setItem('vulnScanResultCache', JSON.stringify(Array.from(this.resultCache)));
    } catch (error) {
      console.error('保存缓存到localStorage失败:', error);
    }
  }

  /**
   * 检查结果是否已通知
   * @param {Object} result 漏洞结果
   * @returns {boolean} 是否已通知
   * @private
   */
  _isAlreadyNotified(result) {
    if (!result) return true;

    // 构建唯一标识
    const resultKey = this._getResultKey(result);

    return this.notifiedResults.has(resultKey);
  }

  /**
   * 标记结果为已通知
   * @param {Object} result 漏洞结果
   * @private
   */
  _markAsNotified(result) {
    if (!result) return;

    // 构建唯一标识
    const resultKey = this._getResultKey(result);

    // 添加到已通知集合
    this.notifiedResults.add(resultKey);
  }

  /**
   * 获取结果的唯一标识
   * @param {Object} result 漏洞结果
   * @returns {string} 唯一标识
   * @private
   */
  _getResultKey(result) {
    // 如果有ID，使用ID
    if (result.id) {
      return `id:${result.id}`;
    }

    // 否则构建一个复合键
    return `${result.vuln_type}:${result.vuln_subtype || ''}:${result.parameter || ''}:${result.url}`;
  }
}

// 创建单例实例
const vulnScanService = new VulnScanService();

// 导出实例
export default vulnScanService;
