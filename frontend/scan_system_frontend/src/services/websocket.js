// src/services/websocket.js - 修改版（增加心跳检测和连接稳定性）
class WebSocketService {
  constructor() {
    this.socket = null;
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10; // 增加最大重连次数
    this.reconnectTimeout = null;
    this.reconnectInterval = 3000; // 减少重连间隔以提高响应性
    this.listeners = {};
    this.url = '';

    // 心跳检测
    this.heartbeatInterval = null;
    this.heartbeatTimeout = null;
    this.missedHeartbeats = 0;
    this.maxMissedHeartbeats = 3;
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
        this.socket = new WebSocket(url);

        // 设置连接超时
        const timeoutId = setTimeout(() => {
          if (!this.isConnected) {
            console.error('WebSocket连接超时');
            reject(new Error('连接超时'));
            this._attemptReconnect();
          }
        }, 5000);

        this.socket.onopen = () => {
          console.log('WebSocket连接成功');
          this.isConnected = true;
          this.reconnectAttempts = 0;
          clearTimeout(timeoutId); // 清除超时

          // 启动心跳检测
          this._startHeartbeat();

          resolve();
        };

        this.socket.onclose = (event) => {
          console.log(`WebSocket连接关闭，代码: ${event.code}, 原因: ${event.reason}`);
          this.isConnected = false;

          // 停止心跳
          this._stopHeartbeat();

          // 尝试重新连接
          this._attemptReconnect();
        };

        this.socket.onerror = (error) => {
          console.error('WebSocket错误:', error);
          if (!this.isConnected) {
            reject(error);
          }
        };

        this.socket.onmessage = (event) => {
          this._handleMessage(event);
        };
      } catch (error) {
        console.error('创建WebSocket连接时出错', error);
        reject(error);
      }
    });
  }

  /**
   * 断开WebSocket连接
   */
  disconnect() {
    this._stopHeartbeat();

    if (this.socket && this.isConnected) {
      this.socket.close();
      this.isConnected = false;
      this.listeners = {};

      // 清除重连计时器
      if (this.reconnectTimeout) {
        clearTimeout(this.reconnectTimeout);
        this.reconnectTimeout = null;
      }
    }
  }

  /**
   * 发送消息到服务器
   * @param {object} data 要发送的数据对象
   */
  send(data) {
    if (this.socket && this.isConnected) {
      try {
        console.log('发送WebSocket消息:', data);
        this.socket.send(JSON.stringify(data));
      } catch (error) {
        console.error('发送WebSocket消息时出错', error);
        this._reconnectNow(); // 如果发送失败，立即尝试重连
        throw error;
      }
    } else {
      console.error('WebSocket未连接，无法发送消息');
      throw new Error('WebSocket未连接');
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
    this.listeners[type].push(callback);
    console.log(`已添加"${type}"类型的监听器，当前监听器数量: ${this.listeners[type].length}`);
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
   * 处理接收到的消息
   * @param {MessageEvent} event WebSocket消息事件
   * @private
   */
  _handleMessage(event) {
    try {
      const data = event.data;
      // 减少日志输出，仅对关键消息记录
      if (data.length < 200) { // 只记录短消息
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

      if (this.listeners[type] && this.listeners[type].length > 0) {
        this.listeners[type].forEach(callback => {
          try {
            callback(message);
          } catch (error) {
            console.error(`执行消息监听器时出错: ${type}`, error);
          }
        });
      }
    } catch (error) {
      console.error('解析WebSocket消息时出错', error);
    }
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
        this.connect(this.url).catch(() => {
          console.error('重新连接失败');
        });
      }, delay);
    } else {
      console.error('达到最大重连次数，放弃重连');
      // 重置重连计数，允许用户手动刷新页面后再次尝试连接
      setTimeout(() => {
        this.reconnectAttempts = 0;
      }, 60000); // 1分钟后重置
    }
  }

  /**
   * 立即重新连接
   * @private
   */
  _reconnectNow() {
    if (this.socket) {
      try {
        this.socket.close();
      } catch (e) {
        // 忽略关闭错误
      }
    }
    this.isConnected = false;
    this._stopHeartbeat();

    // 立即尝试重连
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
    }
    this.reconnectTimeout = setTimeout(() => {
      this.connect(this.url).catch(() => {
        console.error('立即重连失败');
      });
    }, 1000);
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
            this._reconnectNow();
            return;
          }

          // 发送心跳
          this.send({ type: 'ping', timestamp: Date.now() });

          // 设置心跳响应超时
          this.heartbeatTimeout = setTimeout(() => {
            console.warn('心跳响应超时');
          }, 5000);

        } catch (error) {
          console.error('发送心跳消息失败', error);
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