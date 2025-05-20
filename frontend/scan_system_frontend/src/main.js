// src/main.js - 修改版（添加全局WebSocket服务初始化）

import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import ElementPlus from 'element-plus';
import 'element-plus/dist/index.css';
import axios from 'axios';
import vulnScanService from './services/vulnScanService';

// 处理 ResizeObserver 错误
const debounceRAF = (callback) => {
  let timeout;
  return () => {
    cancelAnimationFrame(timeout);
    timeout = requestAnimationFrame(callback);
  };
};

// 更彻底的全局错误处理
window.addEventListener('error', (event) => {
  if (event.message && event.message.includes('ResizeObserver loop')) {
    event.stopImmediatePropagation();
    event.preventDefault();
    return;
  }
}, true);

// 重载 ResizeObserver 来解决循环错误
const _ResizeObserver = window.ResizeObserver;
window.ResizeObserver = class ResizeObserver extends _ResizeObserver {
  constructor(callback) {
    super(debounceRAF(callback));
  }
};

const app = createApp(App);

// 配置axios
app.config.globalProperties.$http = axios;

// 初始化漏洞扫描服务
console.log("初始化全局漏洞扫描服务...");
vulnScanService.init();

// 提供服务到全局
app.config.globalProperties.$vulnScanService = vulnScanService;

// 添加全局页面可见性检测，用于自动重连WebSocket
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    console.log('页面变为可见，检查WebSocket连接状态');
    
    // 检查漏洞扫描服务连接状态
    if (!vulnScanService.getConnectionStatus()) {
      console.log('WebSocket连接已断开，自动重连');
      vulnScanService.reconnect();
    }
  }
});

// 使用插件
app.use(router);
app.use(ElementPlus);

app.mount('#app');

// 添加页面关闭/刷新前的处理
window.addEventListener('beforeunload', () => {
  // 保存缓存状态
  vulnScanService._saveCacheToStorage();
});
