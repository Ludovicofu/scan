// src/services/websocket.js - 改进版
class WebSocketService {
  constructor() {
    this.socket = null;
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10;
    this.reconnectTimeout = null;
    this.reconnectInterval = 3000;
    this.listeners = {};
    this.url = '';
    
    // 心跳检测相关
    this.heartbeatInterval = null;
    this.heartbeatTimeout = null;
    this.missedHeartbeats = 0;
    this.maxMissedHeartbeats = 3;
    
    // 错误计数和日志
    this.errorLog = [];
    this.maxErrorLogs = 10;
    this.lastErrorTime = 0;
    
    // 消息统计
    this.messageStats = {
      sent: 0,
      received: 0,
      errors: 0
    };
  }

  /**
   * 连接WebSocket
   * @param {string} url WebSocket URL
   * @returns {Promise} 连接成功的Promise
   */
  connect(url) {
    console.log('尝试连接WebSocket:', url);
    this.url = url;
    
    return new Promise((resolve, reject) => {
      try {
        // 如果已有连接，先断开
        if (this.socket) {
          try {
            this.socket.close();
          } catch (e) {
            // 忽略关闭错误
          }
          this.socket = null;
        }
        
        // 创建新连接
        this.socket = new WebSocket(url);

        // 设置连接超时
        const timeoutId = setTimeout(() => {
          if (!this.isConnected) {
            const error = new Error('WebSocket连接超时');
            this.logError(error);
            reject(error);
            this._attemptReconnect();
          }
        }, 5000);

        this.socket.onopen = (event) => {
          console.log('WebSocket连接成功', event);
          this.isConnected = true;
          this.reconnectAttempts = 0;
          clearTimeout(timeoutId); // 清除超时
          
          // 发送初始ping消息以验证连接
          this._sendPing();
          
          // 启动心跳检测
          this._startHeartbeat();
          
          resolve();
        };

        this.socket.onclose = (event) => {
          console.log(`WebSocket连接关闭，代码: ${event.code}, 原因: ${event.reason}`);
          
          // 只有在之前连接过的情况下才记录连接断开
          if (this.isConnected) {
            this.isConnected = false;
            
            // 停止心跳
            this._stopHeartbeat();
            
            // 尝试重新连接
            this._attemptReconnect();
            
            // 通知所有监听器连接断开
            this._notifyConnectionStatusChange(false);
          }
        };

        this.socket.onerror = (error) => {
          console.error('WebSocket错误:', error);
          this.logError(error);
          
          if (!this.isConnected) {
            reject(error);
          }
          
          // 通知错误
          this._notifyError(error);
        };

        this.socket.onmessage = (event) => {
          this._handleMessage(event);
        };
      } catch (error) {
        console.error('创建WebSocket连接时出错', error);
        this.logError(error);
        reject(error);
      }
    });
  }

  /**
   * 断开WebSocket连接
   */
  disconnect() {
    this._stopHeartbeat();

    if (this.socket) {
      try {
        this.socket.close();
      } catch (e) {
        console.error('关闭WebSocket时出错', e);
      }
      this.socket = null;
    }
    
    this.isConnected = false;
    
    // 清除监听器
    this.listeners = {};

    // 清除重连计时器
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    
    console.log('WebSocket已断开连接');
  }

  /**
   * 发送消息到服务器
   * @param {object} data 要发送的数据对象
   */
  send(data) {
    if (this.socket && this.isConnected) {
      try {
        const message = JSON.stringify(data);
        this.socket.send(message);
        this.messageStats.sent++;
        
        // 如果消息很大，只打印摘要
        if (message.length > 1000) {
          console.log(`发送WebSocket消息: ${message.substring(0, 200)}... (${message.length}字节)`);
        } else {
          console.log('发送WebSocket消息:', data);
        }
        
        return true;
      } catch (error) {
        console.error('发送WebSocket消息时出错', error);
        this.logError(error);
        this.messageStats.errors++;
        
        // 如果发送失败，检查连接并尝试重连
        this._checkConnectionAndReconnect();
        
        throw error;
      }
    } else {
      const error = new Error('WebSocket未连接，无法发送消息');
      console.error(error.message);
      this.logError(error);
      this.messageStats.errors++;
      throw error;
    }
  }

  /**
   * 添加消息类型监听器
   * @param {string} type 消息类型
   * @param {function} callback 回调函数
   */
  addListener(type, callback) {
    if (!this.listeners[type]) {
      this.listeners[type] = [];
    }
    
    // 检查是否已存在相同的回调
    const exists = this.listeners[type].some(cb => cb === callback);
    if (!exists) {
      this.listeners[type].push(callback);
      console.log(`已添加"${type}"类型的监听器，当前监听器数量: ${this.listeners[type].length}`);
    }
  }

  /**
   * 添加连接状态变化监听器
   * @param {function} callback 回调函数，接收一个布尔参数表示是否连接
   */
  addConnectionListener(callback) {
    this.addListener('_connection_change', callback);
  }

  /**
   * 添加错误监听器
   * @param {function} callback 回调函数，接收错误对象
   */
  addErrorListener(callback) {
    this.addListener('_error', callback);
  }

  /**
   * 移除消息类型监听器
   * @param {string} type 消息类型
   * @param {function} callback 回调函数
   */
  removeListener(type, callback) {
    if (this.listeners[type]) {
      this.listeners[type] = this.listeners[type].filter(cb => cb !== callback);
      console.log(`已移除"${type}"类型的监听器，剩余监听器数量: ${this.listeners[type].length}`);
    }
  }

  /**
   * 获取错误日志
   * @returns {Array} 错误日志数组
   */
  getErrorLogs() {
    return [...this.errorLog];
  }

  /**
   * 获取消息统计
   * @returns {Object} 消息统计对象
   */
  getMessageStats() {
    return {...this.messageStats};
  }

  /**
   * 清除错误日志
   */
  clearErrorLogs() {
    this.errorLog = [];
  }

  /**
   * 记录错误到错误日志
   * @param {Error} error 错误对象
   * @private
   */
  logError(error) {
    const now = new Date();
    
    // 防止短时间内记录过多相同错误
    const minErrorInterval = 1000; // 1秒内只记录一次相同错误
    if (now.getTime() - this.lastErrorTime < minErrorInterval && 
        this.errorLog.length > 0 && 
        this.errorLog[0].message === error.message) {
      // 更新最后一次错误的计数
      this.errorLog[0].count = (this.errorLog[0].count || 1) + 1;
      return;
    }
    
    this.lastErrorTime = now.getTime();
    
    // 添加新错误
    this.errorLog.unshift({
      time: now.toISOString(),
      message: error.message || '未知错误',
      stack: error.stack,
      count: 1
    });
    
    // 限制日志大小
    if (this.errorLog.length > this.maxErrorLogs) {
      this.errorLog.pop();
    }
    
    this.messageStats.errors++;
  }

  /**
   * 通知连接状态变化
   * @param {boolean} connected 是否连接
   * @private
   */
  _notifyConnectionStatusChange(connected) {
    if (this.listeners['_connection_change']) {
      this.listeners['_connection_change'].forEach(callback => {
        try {
          callback(connected);
        } catch (error) {
          console.error('执行连接状态变化监听器时出错', error);
        }
      });
    }
  }

  /**
   * 通知错误
   * @param {Error} error 错误对象
   * @private
   */
  _notifyError(error) {
    if (this.listeners['_error']) {
      this.listeners['_error'].forEach(callback => {
        try {
          callback(error);
        } catch (error) {
          console.error('执行错误监听器时出错', error);
        }
      });
    }
  }

  /**
   * 处理接收到的消息
   * @param {MessageEvent} event WebSocket消息事件
   * @private
   */
  _handleMessage(event) {
    try {
      const data = event.data;
      this.messageStats.received++;
      
      // 避免日志过大
      if (data.length < 500) {
        console.log('收到WebSocket消息:', data);
      } else {
        console.log(`收到WebSocket消息 (${data.length} 字节)`);
      }

      const message = JSON.parse(data);
      const type = message.type;

      // 处理心跳响应
      if (type === 'pong') {
        this._handleHeartbeatResponse();
        return;
      }

      // 处理ping消息
      if (type === 'ping') {
        // 收到ping自动回复pong
        try {
          this.send({ type: 'pong', time: Date.now() });
        } catch (e) {
          console.error('回复pong消息失败', e);
        }
        return;
      }

      // 分发消息到对应的监听器
      if (this.listeners[type] && this.listeners[type].length > 0) {
        this.listeners[type].forEach(callback => {
          try {
            callback(message);
          } catch (error) {
            console.error(`执行消息监听器时出错: ${type}`, error);
            this.logError(error);
          }
        });
      } else {
        console.log(`没有"${type}"类型的监听器`);
      }
    } catch (error) {
      console.error('解析WebSocket消息时出错', error);
      this.logError(error);
    }
  }

  /**
   * 检查连接状态并在需要时尝试重连
   * @private
   */
  _checkConnectionAndReconnect() {
    if (!this.socket || this.socket.readyState > 1) {
      // 如果socket不存在或已关闭/关闭中
      this.isConnected = false;
      this._attemptReconnect();
      return false;
    }
    
    if (this.socket.readyState === 0) {
      // 连接中，等待
      console.log('WebSocket连接中，等待...');
      return false;
    }
    
    return this.isConnected;
  }

  /**
   * 尝试重新连接
   * @private
   */
  _attemptReconnect() {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
    }

    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.log(`尝试重新连接 (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);

      // 使用指数退避策略
      const delay = Math.min(this.reconnectInterval * Math.pow(1.5, this.reconnectAttempts - 1), 30000);

      this.reconnectTimeout = setTimeout(() => {
        this.connect(this.url).catch(error => {
          console.error('重新连接失败', error);
        });
      }, delay);
    } else {
      console.error(`达到最大重连次数(${this.maxReconnectAttempts})，放弃重连`);
      
      // 重置重连计数，允许手动重连
      setTimeout(() => {
        this.reconnectAttempts = 0;
      }, 60000); // 1分钟后重置
    }
  }

  /**
   * 发送ping消息
   * @private
   */
  _sendPing() {
    if (this.isConnected) {
      try {
        this.send({ type: 'ping', time: Date.now() });
      } catch (error) {
        console.error('发送ping消息失败', error);
      }
    }
  }

  /**
   * 启动心跳检测
   * @private
   */
  _startHeartbeat() {
    this._stopHeartbeat(); // 先清除可能存在的心跳

    this.missedHeartbeats = 0;

    // 每15秒发送一次心跳
    this.heartbeatInterval = setInterval(() => {
      if (this.isConnected) {
        try {
          this.missedHeartbeats++;

          // 如果连续错过3次心跳，认为连接已断开
          if (this.missedHeartbeats >= this.maxMissedHeartbeats) {
            console.error(`连续错过${this.missedHeartbeats}次心跳响应，重新连接...`);
            this.isConnected = false;
            this._stopHeartbeat();
            this._attemptReconnect();
            this._notifyConnectionStatusChange(false);
            return;
          }

          // 发送心跳
          this._sendPing();

          // 设置心跳响应超时
          this.heartbeatTimeout = setTimeout(() => {
            console.warn('心跳响应超时');
          }, 5000);

        } catch (error) {
          console.error('发送心跳消息失败', error);
          this.logError(error);
        }
      }
    }, 15000);
  }

  /**
   * 停止心跳检测
   * @private
   */
  _stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }

    if (this.heartbeatTimeout) {
      clearTimeout(this.heartbeatTimeout);
      this.heartbeatTimeout = null;
    }
  }

  /**
   * 处理心跳响应
   * @private
   */
  _handleHeartbeatResponse() {
    this.missedHeartbeats = 0;

    if (this.heartbeatTimeout) {
      clearTimeout(this.heartbeatTimeout);
      this.heartbeatTimeout = null;
    }
  }
}

// 创建实例
const dataCollectionWS = new WebSocketService();
const vulnScanWS = new WebSocketService();
const rulesWS = new WebSocketService();

// 导出实例
export {
  dataCollectionWS,
  vulnScanWS,
  rulesWS
};
