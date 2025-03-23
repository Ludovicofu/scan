<template>
  <div class="scan-progress">
    <div class="progress-header">
      <h3>{{ title }}</h3>
      <div class="status-indicator" :class="statusClass">
        {{ statusText }}
      </div>
    </div>

    <el-progress
      :percentage="progress"
      :status="progressStatus"
      :stroke-width="12"
    ></el-progress>

    <div class="progress-details">
      <div v-if="currentUrl" class="current-url">
        <span class="label">当前URL:</span>
        <span class="value">{{ currentUrl }}</span>
      </div>
      <div v-if="message" class="message">
        <span class="label">状态:</span>
        <span class="value">{{ message }}</span>
      </div>
    </div>

    <div class="actions">
      <el-button
        type="primary"
        size="small"
        :disabled="status === 'scanning'"
        @click="$emit('start')"
      >
        开始扫描
      </el-button>
      <el-button
        type="danger"
        size="small"
        :disabled="status !== 'scanning'"
        @click="$emit('stop')"
      >
        停止扫描
      </el-button>
    </div>
  </div>
</template>

<script>
export default {
  name: 'ScanProgress',
  props: {
    title: {
      type: String,
      default: '扫描进度'
    },
    status: {
      type: String,
      default: 'idle', // idle, scanning, completed, error
    },
    progress: {
      type: Number,
      default: 0
    },
    currentUrl: {
      type: String,
      default: ''
    },
    message: {
      type: String,
      default: ''
    }
  },
  computed: {
    statusText() {
      const statusMap = {
        idle: '空闲',
        scanning: '扫描中',
        completed: '已完成',
        error: '错误'
      };
      return statusMap[this.status] || '未知';
    },
    statusClass() {
      return `status-${this.status}`;
    },
    progressStatus() {
      if (this.status === 'completed') return 'success';
      if (this.status === 'error') return 'exception';
      return '';
    }
  }
};
</script>

<style scoped>
.scan-progress {
  background-color: #f9f9f9;
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 20px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.progress-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.progress-header h3 {
  margin: 0;
  font-size: 16px;
}

.status-indicator {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: bold;
}

.status-idle {
  background-color: #909399;
  color: white;
}

.status-scanning {
  background-color: #409EFF;
  color: white;
}

.status-completed {
  background-color: #67C23A;
  color: white;
}

.status-error {
  background-color: #F56C6C;
  color: white;
}

.progress-details {
  margin-top: 16px;
  padding: 10px;
  background-color: #f2f6fc;
  border-radius: 4px;
}

.current-url, .message {
  display: flex;
  margin-bottom: 8px;
}

.label {
  font-weight: bold;
  min-width: 80px;
  color: #606266;
}

.value {
  word-break: break-all;
}

.actions {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
  gap: 10px;
}
</style>