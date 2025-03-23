<template>
  <div id="app">
    <div class="layout">
      <SidebarMenu class="sidebar" />
      <div class="main-content">
        <router-view/>
      </div>
    </div>
  </div>
</template>

<script>
import SidebarMenu from '@/components/SidebarMenu.vue';

export default {
  name: 'App',
  components: {
    SidebarMenu
  }
};
</script>

<style>
html, body {
  margin: 0;
  padding: 0;
  height: 100%;
  font-family: 'Helvetica Neue', Helvetica, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', '微软雅黑', Arial, sans-serif;
}

#app {
  height: 100%;
}

.layout {
  display: flex;
  height: 100%;
}

.sidebar {
  flex: none;
  width: 220px;
  height: 100%;
}

.main-content {
  flex: 1;
  height: 100%;
  overflow-y: auto;
  background-color: #f0f2f5;
}
</style>