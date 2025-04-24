import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import ElementPlus from 'element-plus';
import 'element-plus/dist/index.css';
import axios from 'axios';

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

// 使用插件
app.use(router);
app.use(ElementPlus);

app.mount('#app');