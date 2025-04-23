// frontend/scan_system_frontend/src/views/RulesPage.vue
<template>
  <div class="rules-page">
    <h1>规则管理</h1>

    <!-- 顶部导航标签 -->
    <el-tabs v-model="activeMainTab" @tab-click="handleMainTabClick">
      <el-tab-pane label="信息收集规则" name="info_collection">
        <!-- 信息收集规则子标签 -->
        <el-tabs v-model="activeInfoTab" @tab-click="handleInfoTabClick">
          <el-tab-pane label="网络信息" name="network"></el-tab-pane>
          <el-tab-pane label="操作系统信息" name="os"></el-tab-pane>
          <el-tab-pane label="组件与服务信息" name="component"></el-tab-pane>
        </el-tabs>

        <!-- 信息收集规则内容 -->
        <div class="rules-content">
          <!-- 网络信息模块显示简化的端口扫描规则 -->
          <template v-if="activeInfoTab === 'network'">
            <PortScanRules />
          </template>

          <!-- 操作系统信息和组件服务信息模块保持原样 -->
          <template v-else>
            <!-- 搜索和筛选 -->
            <div class="rules-search">
              <el-input
                v-model="searchQuery"
                placeholder="搜索规则"
                :prefix-icon="Search"
                clearable
                @input="handleSearch"
                style="width: 300px; margin-right: 10px;"
              ></el-input>

              <el-button type="primary" @click="handleAddInfoRule">新增规则</el-button>
            </div>

            <!-- 被动扫描规则 -->
            <PassiveScanRules
              :rules="filteredPassiveRules"
              :loading="infoRulesLoading"
              @edit-rule="editInfoRule"
              @delete-rule="deleteInfoRule"
            />

            <!-- 主动扫描规则 -->
            <ActiveScanRules
              :rules="filteredActiveRules"
              :loading="infoRulesLoading"
              @edit-rule="editInfoRule"
              @delete-rule="deleteInfoRule"
            />
          </template>
        </div>
      </el-tab-pane>

      <el-tab-pane label="漏洞检测规则" name="vuln_scan">
        <!-- 漏洞检测规则子标签 -->
        <el-tabs v-model="activeVulnTab" @tab-click="handleVulnTabClick">
          <el-tab-pane label="SQL注入" name="sql_injection"></el-tab-pane>
          <el-tab-pane label="XSS" name="xss"></el-tab-pane>
          <el-tab-pane label="文件包含" name="file_inclusion"></el-tab-pane>
          <el-tab-pane label="命令注入" name="command_injection"></el-tab-pane>
          <el-tab-pane label="SSRF" name="ssrf"></el-tab-pane>
          <el-tab-pane label="XXE" name="xxe"></el-tab-pane>
          <el-tab-pane label="其他" name="other"></el-tab-pane>
        </el-tabs>

        <!-- 漏洞检测规则内容 -->
        <div class="rules-content">
          <p>漏洞检测规则功能当前不可用，请等待系统更新。</p>
        </div>
      </el-tab-pane>
    </el-tabs>

    <!-- 信息收集规则编辑对话框 -->
    <InfoRuleEditDialog
      :visible="infoRuleDialogVisible"
      :is-edit="isEditMode"
      :rule-form="infoRuleForm"
      :active-tab="activeInfoTab"
      @close="infoRuleDialogVisible = false"
      @submit="submitInfoRule"
    />
  </div>
</template>

<script>
import { rulesAPI } from '@/services/api';
import { Search } from '@element-plus/icons-vue';
import PortScanRules from '@/components/rules/PortScanRules.vue';
import PassiveScanRules from '@/components/rules/PassiveScanRules.vue';
import ActiveScanRules from '@/components/rules/ActiveScanRules.vue';
import InfoRuleEditDialog from '@/components/rules/InfoRuleEditDialog.vue';
import { ElMessage, ElMessageBox } from 'element-plus';

export default {
  name: 'RulesPage',
  components: {
    PortScanRules,
    PassiveScanRules,
    ActiveScanRules,
    InfoRuleEditDialog
  },
  data() {
    return {
      // 导航标签
      activeMainTab: 'info_collection', // 主标签
      activeInfoTab: 'network', // 信息收集子标签
      activeVulnTab: 'sql_injection', // 漏洞检测子标签

      // 规则数据
      infoRules: [], // 信息收集规则列表
      vulnRules: [], // 漏洞检测规则列表
      infoRulesLoading: false,
      vulnRulesLoading: false,

      // 搜索和筛选
      searchQuery: '',
      Search, // 引用Search图标组件

      // 规则对话框
      infoRuleDialogVisible: false,
      isEditMode: false,
      infoRuleForm: {
        id: null,
        module: 'network',
        scan_type: 'passive',
        description: '',
        rule_type: 'response_content',
        match_values: '',
        behaviors: ''
      }
    };
  },
  computed: {
    // 过滤后的被动扫描规则
    filteredPassiveRules() {
      if (!Array.isArray(this.infoRules)) {
        console.warn("infoRules不是数组:", this.infoRules);
        return [];
      }

      const query = this.searchQuery.toLowerCase();
      return this.infoRules.filter(rule => {
        // 确保rule和rule.scan_type存在
        if (!rule || typeof rule.scan_type === 'undefined') {
          console.warn("无效的规则对象:", rule);
          return false;
        }

        return rule.scan_type === 'passive' &&
          (query === '' ||
           (rule.description && rule.description.toLowerCase().includes(query)) ||
           (rule.match_values && rule.match_values.toLowerCase().includes(query)));
      });
    },

    // 过滤后的主动扫描规则
    filteredActiveRules() {
      if (!Array.isArray(this.infoRules)) {
        console.warn("infoRules不是数组:", this.infoRules);
        return [];
      }

      const query = this.searchQuery.toLowerCase();
      return this.infoRules.filter(rule => {
        // 确保rule和rule.scan_type存在
        if (!rule || typeof rule.scan_type === 'undefined') {
          console.warn("无效的规则对象:", rule);
          return false;
        }

        // 不在表格中显示端口扫描规则，由专用组件管理
        if (rule.rule_type === 'port') {
          return false;
        }

        return rule.scan_type === 'active' &&
          (query === '' ||
           (rule.description && rule.description.toLowerCase().includes(query)) ||
           (rule.match_values && rule.match_values.toLowerCase().includes(query)) ||
           (rule.behaviors && rule.behaviors.toLowerCase().includes(query)));
      });
    }
  },
  created() {
    // 加载当前标签页所需规则
    this.loadCurrentTabRules();
  },
  methods: {
    // 标签切换处理
    handleMainTabClick() {
      this.loadCurrentTabRules();
    },

    handleInfoTabClick() {
      this.loadCurrentTabRules();
    },

    handleVulnTabClick() {
      // 暂不实现
    },

    // 加载当前标签页所需规则
    loadCurrentTabRules() {
      if (this.activeMainTab === 'info_collection') {
        if (this.activeInfoTab !== 'network') {
          // 对于非网络信息模块，加载常规规则
          this.fetchInfoRules();
        }
        // 网络信息模块的端口扫描规则由PortScanRules组件自行加载
      } else if (this.activeMainTab === 'vuln_scan') {
        // 漏洞检测规则暂不实现
      }
    },

    // 数据操作方法
    async fetchInfoRules() {
      // 如果是网络信息模块，不需要在这里获取规则列表
      if (this.activeInfoTab === 'network') {
        return;
      }

      console.log(`开始获取 ${this.activeInfoTab} 模块规则`);
      this.infoRulesLoading = true;
      try {
        // 使用模块API获取规则
        const response = await rulesAPI.getInfoCollectionRulesByModule(this.activeInfoTab);
        console.log(`获取 ${this.activeInfoTab} 模块规则响应:`, response);

        // 处理不同的响应格式
        if (response && Array.isArray(response.results)) {
          // 如果返回的是带有results字段的对象（分页格式）
          this.infoRules = response.results;
        } else if (Array.isArray(response)) {
          // 如果直接返回了数组
          this.infoRules = response;
        } else {
          // 其他情况，可能是单个对象或其他格式
          console.warn("意外的响应格式:", response);
          this.infoRules = Array.isArray(response) ? response : [];
        }

        // 确保infoRules始终是一个数组
        if (!this.infoRules || !Array.isArray(this.infoRules)) {
          console.warn("规则数据不是数组，重置为空数组");
          this.infoRules = [];
        }

        console.log(`获取到 ${this.infoRules.length} 条规则数据`);
      } catch (error) {
        console.error(`获取 ${this.activeInfoTab} 模块规则失败:`, error);

        // 初始化为空数组
        this.infoRules = [];

        // 提示用户
        ElMessage.error(`获取 ${this.activeInfoTab} 模块规则失败`);
      } finally {
        this.infoRulesLoading = false;
      }
    },

    // 搜索和筛选
    handleSearch() {
      // 搜索在计算属性中实现
    },

    // 规则编辑相关 - 仅适用于非网络信息模块
    handleAddInfoRule() {
      if (this.activeInfoTab === 'network') {
        ElMessage.info('网络信息模块使用简化的端口扫描规则管理，请直接修改端口列表');
        return;
      }

      this.isEditMode = false;
      this.infoRuleForm = {
        id: null,
        module: this.activeInfoTab,
        scan_type: 'passive',
        description: '',
        rule_type: 'response_content',
        match_values: '',
        behaviors: ''
      };
      this.infoRuleDialogVisible = true;
    },

    editInfoRule(rule) {
      if (this.activeInfoTab === 'network') {
        return;
      }

      this.isEditMode = true;
      this.infoRuleForm = {
        id: rule.id,
        module: rule.module,
        scan_type: rule.scan_type,
        description: rule.description,
        rule_type: rule.rule_type,
        match_values: rule.match_values,
        behaviors: rule.behaviors || ''
      };
      this.infoRuleDialogVisible = true;
    },

    async submitInfoRule(formData) {
      if (this.activeInfoTab === 'network') {
        return;
      }

      try {
        if (this.isEditMode) {
          // 更新规则
          await rulesAPI.updateInfoCollectionRule(this.infoRuleForm.id, formData);
          ElMessage.success('规则更新成功');
        } else {
          // 创建规则
          await rulesAPI.createInfoCollectionRule(formData);
          ElMessage.success('规则创建成功');
        }

        // 关闭对话框
        this.infoRuleDialogVisible = false;

        // 重新获取规则
        this.fetchInfoRules();
      } catch (error) {
        console.error('保存规则失败', error);
        ElMessage.error('保存规则失败');
      }
    },

    async deleteInfoRule(id) {
      if (this.activeInfoTab === 'network') {
        return;
      }

      try {
        await ElMessageBox.confirm('确认删除该规则?', '提示', {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
        });

        await rulesAPI.deleteInfoCollectionRule(id);
        ElMessage.success('删除成功');

        // 重新获取规则
        this.fetchInfoRules();
      } catch (error) {
        if (error !== 'cancel') {
          console.error('删除规则失败', error);
          ElMessage.error('删除规则失败');
        }
      }
    }
  }
};
</script>

<style scoped>
.rules-page {
  padding: 20px;
}

h1 {
  margin-bottom: 20px;
  font-size: 24px;
  color: #303133;
}

.rules-content {
  margin-top: 20px;
}

.rules-search {
  display: flex;
  margin-bottom: 20px;
}
</style>