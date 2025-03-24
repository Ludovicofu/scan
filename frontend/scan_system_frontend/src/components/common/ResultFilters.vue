<template>
  <div class="result-filters">
    <el-form :inline="true" :model="filterForm" class="filter-form" size="small">
      <!-- 通用过滤器 -->
      <el-form-item label="时间范围">
        <el-date-picker
          v-model="dateRange"
          type="daterange"
          range-separator="至"
          start-placeholder="开始日期"
          end-placeholder="结束日期"
          format="YYYY-MM-DD"
          value-format="YYYY-MM-DD"
          @change="handleDateRangeChange"
        ></el-date-picker>
      </el-form-item>

      <el-form-item label="主机/IP">
        <el-input
          v-model="filterForm.host"
          placeholder="输入主机名或IP"
          clearable
          @input="handleFilterChange"
        ></el-input>
      </el-form-item>

      <!-- 条件过滤器 -->
      <template v-if="type === 'info'">
        <el-form-item label="模块">
          <el-select
            v-model="filterForm.module"
            placeholder="选择模块"
            clearable
            @change="handleFilterChange"
          >
            <el-option label="网络信息" value="network"></el-option>
            <el-option label="操作系统信息" value="os"></el-option>
            <el-option label="组件与服务信息" value="component"></el-option>
          </el-select>
        </el-form-item>

        <el-form-item label="规则类型">
          <el-select
            v-model="filterForm.rule_type"
            placeholder="选择规则类型"
            clearable
            @change="handleFilterChange"
          >
            <el-option label="状态码判断" value="status_code"></el-option>
            <el-option label="响应内容匹配" value="response_content"></el-option>
            <el-option label="HTTP 头匹配" value="header"></el-option>
          </el-select>
        </el-form-item>
      </template>

      <template v-else-if="type === 'vuln'">
        <el-form-item label="漏洞类型">
          <el-select
            v-model="filterForm.vuln_type"
            placeholder="选择漏洞类型"
            clearable
            @change="handleFilterChange"
          >
            <el-option label="SQL注入" value="sql_injection"></el-option>
            <el-option label="XSS跨站脚本" value="xss"></el-option>
            <el-option label="文件包含" value="file_inclusion"></el-option>
            <el-option label="命令注入" value="command_injection"></el-option>
            <el-option label="SSRF" value="ssrf"></el-option>
            <el-option label="XXE" value="xxe"></el-option>
            <el-option label="其他" value="other"></el-option>
          </el-select>
        </el-form-item>

        <el-form-item label="严重程度">
          <el-select
            v-model="filterForm.severity"
            placeholder="选择严重程度"
            clearable
            @change="handleFilterChange"
          >
            <el-option label="高" value="high"></el-option>
            <el-option label="中" value="medium"></el-option>
            <el-option label="低" value="low"></el-option>
            <el-option label="信息" value="info"></el-option>
          </el-select>
        </el-form-item>
      </template>

      <el-form-item label="扫描类型">
        <el-select
          v-model="filterForm.scan_type"
          placeholder="选择扫描类型"
          clearable
          @change="handleFilterChange"
        >
          <el-option label="被动扫描" value="passive"></el-option>
          <el-option label="主动扫描" value="active"></el-option>
        </el-select>
      </el-form-item>

      <!-- 搜索框和按钮 -->
      <el-form-item>
        <el-input
          v-model="filterForm.keyword"
          placeholder="搜索关键词"
          clearable
          @input="handleFilterChange"
        >
          <template #append>
            <el-button :icon="Search" @click="handleFilterChange"></el-button>
          </template>
        </el-input>
      </el-form-item>

      <el-form-item>
        <el-button type="primary" @click="handleFilterChange">筛选</el-button>
        <el-button @click="resetFilters">重置</el-button>
      </el-form-item>
    </el-form>
  </div>
</template>

<script>
import { Search } from '@element-plus/icons-vue';

export default {
  name: 'ResultFilters',
  props: {
    type: {
      type: String,
      default: 'info', // 'info' 或 'vuln'
      validator: (value) => ['info', 'vuln'].includes(value)
    }
  },
  data() {
    return {
      dateRange: null,
      filterForm: {
        host: '',
        keyword: '',
        date_from: '',
        date_to: '',
        // 信息收集相关过滤条件
        module: '',
        rule_type: '',
        // 漏洞扫描相关过滤条件
        vuln_type: '',
        severity: '',
        // 共有的过滤条件
        scan_type: ''
      },
      Search // 引入Search图标组件
    };
  },
  methods: {
    handleDateRangeChange(val) {
      if (val) {
        this.filterForm.date_from = val[0];
        this.filterForm.date_to = val[1];
      } else {
        this.filterForm.date_from = '';
        this.filterForm.date_to = '';
      }
      this.handleFilterChange();
    },
    handleFilterChange() {
      // 向父组件发送过滤条件变更事件
      this.$emit('filter-change', { ...this.filterForm });
    },
    resetFilters() {
      this.dateRange = null;
      this.filterForm = {
        host: '',
        keyword: '',
        date_from: '',
        date_to: '',
        module: '',
        rule_type: '',
        vuln_type: '',
        severity: '',
        scan_type: ''
      };
      this.handleFilterChange();
    }
  }
};
</script>

<style scoped>
.result-filters {
  background-color: #f9f9f9;
  padding: 16px;
  border-radius: 8px;
  margin-bottom: 20px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.filter-form {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

@media (max-width: 768px) {
  .filter-form {
    flex-direction: column;
  }

  .el-form-item {
    margin-right: 0;
    margin-bottom: 10px;
  }
}
</style>