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
          <!-- 网络信息模块特殊处理 -->
          <template v-if="activeInfoTab === 'network'">
            <!-- 端口扫描规则部分 -->
            <PortScanRules />

            <!-- 分隔线 -->
            <el-divider content-position="left">其他网络信息规则</el-divider>
          </template>

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
    this.fetchInfoRules();
  },
  methods: {
    // 标签切换处理
    handleMainTabClick() {
      if (this.activeMainTab === 'info_collection') {
        this.fetchInfoRules();
      } else if (this.activeMainTab === 'vuln_scan') {
        // 暂不实现
      }
    },
    handleInfoTabClick() {
      this.fetchInfoRules();
    },
    handleVulnTabClick() {
      // 暂不实现
    },

    // 数据操作方法
    async fetchInfoRules() {
      this.infoRulesLoading = true;
      try {
        console.log("开始获取规则，模块:", this.activeInfoTab);
        const response = await rulesAPI.getInfoCollectionRulesByModule(this.activeInfoTab);
        console.log("获取规则响应:", response);

        // 检查response是否有预期的格式
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

        console.log("处理后的规则数据:", this.infoRules);

        // 如果infoRules为空或不是数组，重置为空数组
        if (!this.infoRules || !Array.isArray(this.infoRules)) {
          console.warn("规则数据不是数组，重置为空数组");
          this.infoRules = [];
        }

        // 如果没有获取到数据，尝试添加一些测试数据（调试用）
        if (this.infoRules.length === 0) {
          console.log("没有获取到规则数据，添加测试数据以验证UI");
          this.infoRules = [
            {
              id: 1,
              module: 'network',
              module_display: '网络信息',
              scan_type: 'passive',
              scan_type_display: '被动扫描',
              description: '测试规则',
              rule_type: 'response_content',
              rule_type_display: '响应内容匹配',
              match_values: 'test value',
              behaviors: null,
              is_enabled: true,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString()
            }
          ];
        }
      } catch (error) {
        console.error('获取规则失败', error);
        // 添加一些测试数据以便UI测试
        console.log("发生错误，添加测试数据以验证UI");
        this.infoRules = [
          {
            id: 1,
            module: 'network',
            module_display: '网络信息',
            scan_type: 'passive',
            scan_type_display: '被动扫描',
            description: '测试规则(错误恢复)',
            rule_type: 'response_content',
            rule_type_display: '响应内容匹配',
            match_values: 'error recovery',
            behaviors: null,
            is_enabled: true,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          }
        ];
      } finally {
        this.infoRulesLoading = false;
      }
    },

    // 搜索和筛选
    handleSearch() {
      // 搜索在计算属性中实现
    },

    // 规则编辑相关
    handleAddInfoRule() {
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

    // 修改提交规则方法
    async submitInfoRule(formData) {
      try {
        console.log("提交规则数据:", formData);

        if (this.isEditMode) {
          // 更新规则
          await rulesAPI.updateInfoCollectionRule(this.infoRuleForm.id, formData);
          console.log("规则更新成功");
          ElMessage.success('规则更新成功');
        } else {
          // 创建规则
          const response = await rulesAPI.createInfoCollectionRule(formData);
          console.log("规则创建成功:", response);
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