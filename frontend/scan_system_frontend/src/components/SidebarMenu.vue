<template>
  <div class="sidebar">
    <div class="sidebar-header">
      <h2>被动代理漏洞扫描系统</h2>
    </div>
    <div class="sidebar-menu">
      <router-link to="/" class="menu-item" active-class="active">
        <el-icon><HomeFilled /></el-icon>
        <span>首页</span>
      </router-link>
      <router-link to="/info-results" class="menu-item" active-class="active">
        <el-icon><Document /></el-icon>
        <span>信息收集</span>
      </router-link>
      <router-link to="/vuln-results" class="menu-item" active-class="active">
        <el-icon><Warning /></el-icon>
        <span>漏洞检测</span>
      </router-link>
      <router-link to="/rules" class="menu-item" active-class="active">
        <el-icon><Setting /></el-icon>
        <span>规则管理</span>
      </router-link>
      <router-link to="/settings" class="menu-item" active-class="active">
        <el-icon><Tools /></el-icon>
        <span>系统设置</span>
      </router-link>
    </div>
    <div class="sidebar-footer">
      <p>版本: 1.0.0</p>
    </div>
  </div>
</template>

<script>
import { HomeFilled, Document, Warning, Setting, Tools } from '@element-plus/icons-vue';

export default {
  name: 'SidebarMenu',
  components: {
    HomeFilled,
    Document,
    Warning,
    Setting,
    Tools
  }
};
</script>

<style scoped>
.sidebar {
  display: flex;
  flex-direction: column;
  width: 220px;
  height: 100%;
  background-color: #001529;
  color: white;
}

.sidebar-header {
  padding: 16px;
  border-bottom: 1px solid #003a70;
}

.sidebar-header h2 {
  margin: 0;
  font-size: 18px;
  text-align: center;
}

.sidebar-menu {
  flex: 1;
  padding: 16px 0;
}

.menu-item {
  display: flex;
  align-items: center;
  padding: 12px 24px;
  color: #b0b0b0;
  text-decoration: none;
  transition: background-color 0.3s;
}

.menu-item:hover {
  background-color: #002140;
  color: white;
}

.menu-item.active {
  background-color: #1890ff;
  color: white;
}

.menu-item .el-icon {
  margin-right: 8px;
  font-size: 18px;
}

.sidebar-footer {
  padding: 16px;
  border-top: 1px solid #003a70;
  text-align: center;
  font-size: 12px;
  color: #8c8c8c;
}
</style>