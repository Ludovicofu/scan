// 首先定义WebSocketService类
class WebSocketService {
  constructor() {
    this.socket = null;
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectTimeout = null;
    this.reconnectInterval = 3000; // 3秒重连间隔
    this.listeners = {};
    this.url = '';
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

        this.socket.onopen = () => {
          console.log('WebSocket连接成功');
          this.isConnected = true;
          this.reconnectAttempts = 0;
          resolve();
        };

        this.socket.onmessage = (event) => {
          this._handleMessage(event);
        };

        this.socket.onclose = (event) => {
          console.log('WebSocket连接关闭', event);
          this.isConnected = false;
          this._attemptReconnect();
        };

        this.socket.onerror = (error) => {
          console.error('WebSocket错误', error);
          reject(error);
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
        this.socket.send(JSON.stringify(data));
      } catch (error) {
        console.error('发送WebSocket消息时出错', error);
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
  }

  /**
   * 移除消息类型监听器
   * @param {string} type 消息类型
   * @param {function} callback 回调函数
   */
  removeListener(type, callback) {
    if (this.listeners[type]) {
      this.listeners[type] = this.listeners[type].filter(cb => cb !== callback);
    }
  }

  /**
   * 处理接收到的消息
   * @param {MessageEvent} event WebSocket消息事件
   * @private
   */
  _handleMessage(event) {
    try {
      const message = JSON.parse(event.data);
      const type = message.type;

      if (this.listeners[type]) {
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

      this.reconnectTimeout = setTimeout(() => {
        this.connect(this.url).catch(() => {
          console.error('重新连接失败');
        });
      }, this.reconnectInterval);
    } else {
      console.error('达到最大重连次数，放弃重连');
    }
  }
}

// 然后创建实例
const dataCollectionWS = new WebSocketService();
const vulnScanWS = new WebSocketService();
const rulesWS = new WebSocketService();

// 最后导出实例
export {
  dataCollectionWS,
  vulnScanWS,
  rulesWS
};