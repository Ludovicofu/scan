import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import ElementPlus from 'element-plus';
import 'element-plus/dist/index.css';
import axios from 'axios';

const app = createApp(App);

// 配置axios
app.config.globalProperties.$http = axios;

// 使用插件
app.use(router);
app.use(ElementPlus);

app.mount('#app');