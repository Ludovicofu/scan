// frontend/scan_system_frontend/src/components/rules/FileInclusionRules.vue
<template>
  <div class="fileinclusion-rules">
    <h3>文件包含扫描设置</h3>
    <div class="rules-container">
      <!-- LFI 本地文件包含载荷 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">本地文件包含载荷</span>
            <span class="rule-desc">添加用于测试本地文件包含(LFI)漏洞的路径遍历载荷</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editLfiPayloads"
              v-if="!isEditingLfi">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveLfiPayloads">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditLfi">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingLfi" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadLfiFailed" class="error-state">
          <el-alert
            title="加载本地文件包含规则失败"
            type="error"
            description="请添加规则"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingLfi" class="payloads-list">
            <div v-for="(payload, index) in lfiPayloads" :key="index" class="payload-item">
              {{ payload }}
            </div>
            <div v-if="lfiPayloads.length === 0" class="no-payload">
              没有配置本地文件包含载荷，点击"修改"添加载荷
            </div>
          </div>
          <div v-else class="payloads-edit">
            <el-input
              type="textarea"
              v-model="lfiPayloadsText"
              :rows="8"
              placeholder="请输入本地文件包含载荷，每行一个"
            ></el-input>
            <div class="hint">
              样例: ../../../etc/passwd, ../../../../Windows/win.ini, ..././..././..././etc/passwd
            </div>
          </div>
        </div>
      </div>

      <!-- RFI 远程文件包含载荷 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">远程文件包含载荷</span>
            <span class="rule-desc">添加用于测试远程文件包含(RFI)漏洞的URL载荷</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editRfiPayloads"
              v-if="!isEditingRfi">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveRfiPayloads">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditRfi">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingRfi" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadRfiFailed" class="error-state">
          <el-alert
            title="加载远程文件包含规则失败"
            type="error"
            description="请添加规则"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingRfi" class="payloads-list">
            <div v-for="(payload, index) in rfiPayloads" :key="index" class="payload-item">
              {{ payload }}
            </div>
            <div v-if="rfiPayloads.length === 0" class="no-payload">
              没有配置远程文件包含载荷，点击"修改"添加载荷
            </div>
          </div>
          <div v-else class="payloads-edit">
            <el-input
              type="textarea"
              v-model="rfiPayloadsText"
              :rows="8"
              placeholder="请输入远程文件包含载荷，每行一个"
            ></el-input>
            <div class="hint">
              样例: http://attacker.com/shell.php, https://evil.com/malware.txt?
            </div>
          </div>
        </div>
      </div>

      <!-- 文件包含匹配模式 -->
      <div class="rule-section">
        <div class="rules-header">
          <div class="rule-info">
            <span class="rule-title">文件包含匹配模式</span>
            <span class="rule-desc">添加用于检测文件包含成功的匹配模式</span>
          </div>
          <div class="rule-actions">
            <el-button
              type="primary"
              size="small"
              @click="editMatchPatterns"
              v-if="!isEditingPatterns">
              修改
            </el-button>
            <template v-else>
              <el-button
                type="success"
                size="small"
                @click="saveMatchPatterns">
                保存
              </el-button>
              <el-button
                type="info"
                size="small"
                @click="cancelEditPatterns">
                取消
              </el-button>
            </template>
          </div>
        </div>

        <div v-if="isLoadingPatterns" class="loading-state">
          <el-skeleton :rows="3" animated />
        </div>
        <div v-else-if="loadPatternsFailed" class="error-state">
          <el-alert
            title="加载文件包含匹配模式失败"
            type="error"
            description="请添加规则"
            :closable="false"
            show-icon
          />
        </div>

        <div v-else class="rules-content">
          <div v-if="!isEditingPatterns" class="patterns-display">
            <el-descriptions :column="1" border v-if="Object.keys(filePatterns).length > 0">
              <el-descriptions-item v-for="(patterns, fileType) in filePatterns" :key="fileType" :label="getFileTypeLabel(fileType)">
                <div class="pattern-list">
                  <div v-for="(pattern, index) in patterns" :key="index" class="pattern-item">
                    {{ pattern }}
                  </div>
                </div>
              </el-descriptions-item>
            </el-descriptions>
            <div v-if="Object.keys(filePatterns).length === 0" class="no-patterns">
              没有配置文件包含匹配模式，点击"修改"添加匹配模式
            </div>
          </div>
          <div v-else class="patterns-edit">
            <p class="context-edit-hint">请以JSON格式编辑文件匹配模式：</p>
            <el-input
              type="textarea"
              v-model="filePatternsText"
              :rows="10"
              placeholder="请输入文件包含匹配模式 (JSON格式)"
            ></el-input>
            <div class="hint">
              样例: {"linux_config": ["root:x:0:0", "bin:x:", "sbin:"],
                    "windows_ini": ["[fonts]", "[extensions]", "[mci extensions]"],
                    "php_info": ["PHP Version", "Configure Command", "PHP API"]}
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { rulesAPI } from '@/services/api';
import { ElMessage } from 'element-plus';

export default {
  name: 'FileInclusionRules',
  data() {
    return {
      // 本地文件包含载荷
      isEditingLfi: false,
      isLoadingLfi: false,
      loadLfiFailed: false,
      lfiPayloads: [],
      lfiPayloadsText: '',
      lfiRuleId: null,  // 用于存储规则ID，便于更新

      // 远程文件包含载荷
      isEditingRfi: false,
      isLoadingRfi: false,
      loadRfiFailed: false,
      rfiPayloads: [],
      rfiPayloadsText: '',
      rfiRuleId: null,  // 用于存储规则ID，便于更新

      // 文件包含匹配模式
      isEditingPatterns: false,
      isLoadingPatterns: false,
      loadPatternsFailed: false,
      filePatterns: {},
      filePatternsText: '',
      patternsRuleId: null  // 用于存储规则ID，便于更新
    };
  },
  created() {
    this.fetchFileInclusionRules();
  },
  methods: {
    async fetchFileInclusionRules() {
      // 获取所有文件包含规则
      this.fetchLfiPayloads();
      this.fetchRfiPayloads();
      this.fetchFilePatterns();
    },

    async fetchLfiPayloads() {
      this.isLoadingLfi = true;
      this.loadLfiFailed = false;

      try {
        // 获取本地文件包含载荷规则
        const rules = await this.fetchVulnScanRulesByType('file_inclusion', 'lfi');

        if (rules.length > 0) {
          // 找到LFI规则
          const rule = rules[0];  // 使用第一条规则
          this.lfiRuleId = rule.id;

          // 解析载荷
          this.lfiPayloads = this.parseRuleContent(rule.rule_content);
          this.lfiPayloadsText = this.lfiPayloads.join('\n');

          console.log("找到本地文件包含规则:", rule);
        } else {
          console.log("未找到本地文件包含规则");
          // 初始化为空
          this.lfiPayloads = [];
          this.lfiPayloadsText = '';
          this.lfiRuleId = null;
        }
      } catch (error) {
        console.error('获取本地文件包含规则失败', error);
        this.loadLfiFailed = true;
        
        // 初始化为空
        this.lfiPayloads = [];
        this.lfiPayloadsText = '';

        ElMessage.error('获取本地文件包含规则失败，请手动添加规则');
      } finally {
        this.isLoadingLfi = false;
      }
    },

    async fetchRfiPayloads() {
      this.isLoadingRfi = true;
      this.loadRfiFailed = false;

      try {
        // 获取远程文件包含载荷规则
        const rules = await this.fetchVulnScanRulesByType('file_inclusion', 'rfi');

        if (rules.length > 0) {
          // 找到RFI规则
          const rule = rules[0];  // 使用第一条规则
          this.rfiRuleId = rule.id;

          // 解析载荷
          this.rfiPayloads = this.parseRuleContent(rule.rule_content);
          this.rfiPayloadsText = this.rfiPayloads.join('\n');

          console.log("找到远程文件包含规则:", rule);
        } else {
          console.log("未找到远程文件包含规则");
          // 初始化为空
          this.rfiPayloads = [];
          this.rfiPayloadsText = '';
          this.rfiRuleId = null;
        }
      } catch (error) {
        console.error('获取远程文件包含规则失败', error);
        this.loadRfiFailed = true;
        
        // 初始化为空
        this.rfiPayloads = [];
        this.rfiPayloadsText = '';

        ElMessage.error('获取远程文件包含规则失败，请手动添加规则');
      } finally {
        this.isLoadingRfi = false;
      }
    },

    async fetchFilePatterns() {
      this.isLoadingPatterns = true;
      this.loadPatternsFailed = false;

      try {
        // 获取文件包含匹配模式规则
        const rules = await this.fetchVulnScanRulesByType('file_inclusion', 'patterns');

        if (rules.length > 0) {
          // 找到匹配模式规则
          const rule = rules[0];  // 使用第一条规则
          this.patternsRuleId = rule.id;

          // 解析匹配模式
          try {
            const ruleContent = JSON.parse(rule.rule_content);
            if (ruleContent.patterns && typeof ruleContent.patterns === 'object') {
              this.filePatterns = ruleContent.patterns;
              this.filePatternsText = JSON.stringify(ruleContent.patterns, null, 2);
            } else {
              throw new Error("规则内容格式不正确");
            }
          } catch (e) {
            console.error("解析文件包含匹配模式失败:", e);
            throw e;
          }

          console.log("找到文件包含匹配模式规则:", rule);
        } else {
          console.log("未找到文件包含匹配模式规则");
          // 初始化为空
          this.filePatterns = {};
          this.filePatternsText = '';
          this.patternsRuleId = null;
        }
      } catch (error) {
        console.error('获取文件包含匹配模式规则失败', error);
        this.loadPatternsFailed = true;
        
        // 初始化为空
        this.filePatterns = {};
        this.filePatternsText = '';

        ElMessage.error('获取文件包含匹配模式规则失败，请手动添加规则');
      } finally {
        this.isLoadingPatterns = false;
      }
    },

    // 辅助方法：根据类型获取漏洞扫描规则
    async fetchVulnScanRulesByType(vulnType, subType) {
      try {
        // 获取指定类型的漏洞扫描规则
        const response = await rulesAPI.getVulnScanRulesByType(vulnType);

        // 从结果中筛选出子类型匹配的规则
        let rules = [];
        if (Array.isArray(response)) {
          rules = response;
        } else if (response && Array.isArray(response.results)) {
          rules = response.results;
        }

        // 过滤子类型
        return rules.filter(rule => {
          try {
            const ruleData = JSON.parse(rule.rule_content);
            return ruleData.subType === subType;
          } catch (e) {
            // 如果解析失败，检查rule_content中是否包含子类型标识
            return rule.rule_content.includes(`"subType":"${subType}"`) ||
                  rule.rule_content.includes(`"subType": "${subType}"`);
          }
        });
      } catch (error) {
        console.error(`获取${vulnType}/${subType}类型规则失败`, error);
        return [];
      }
    },

    // 解析规则内容
    parseRuleContent(ruleContent) {
      try {
        const data = JSON.parse(ruleContent);
        return Array.isArray(data.payloads) ? data.payloads : [];
      } catch (e) {
        console.error('解析规则内容失败', e);
        return [];
      }
    },

    // 获取文件类型标签
    getFileTypeLabel(fileType) {
      const labels = {
        "linux_etc_passwd": "Linux /etc/passwd 文件",
        "linux_etc_shadow": "Linux /etc/shadow 文件",
        "windows_win_ini": "Windows win.ini 文件",
        "apache_conf": "Apache 配置文件",
        "php_info": "PHP 信息页",
        "linux_config": "Linux 配置文件",
        "windows_ini": "Windows INI 文件"
      };
      return labels[fileType] || fileType;
    },

    // 编辑方法
    editLfiPayloads() {
      this.isEditingLfi = true;
    },

    cancelEditLfi() {
      this.isEditingLfi = false;
      this.lfiPayloadsText = this.lfiPayloads.join('\n');
    },

    editRfiPayloads() {
      this.isEditingRfi = true;
    },

    cancelEditRfi() {
      this.isEditingRfi = false;
      this.rfiPayloadsText = this.rfiPayloads.join('\n');
    },

    editMatchPatterns() {
      this.isEditingPatterns = true;
      
      // 如果没有内容，提供一个空对象结构作为模板
      if (!this.filePatternsText) {
        this.filePatternsText = JSON.stringify({
          "linux_etc_passwd": [],
          "windows_win_ini": []
        }, null, 2);
      }
    },

    cancelEditPatterns() {
      this.isEditingPatterns = false;
      this.filePatternsText = JSON.stringify(this.filePatterns, null, 2);
    },

    // 保存方法
    async saveLfiPayloads() {
      try {
        // 处理文本框中的内容，分割为载荷数组
        const payloads = this.lfiPayloadsText
          .split('\n')
          .map(line => line.trim())
          .filter(line => line);

        // 准备规则数据
        const ruleData = {
          vuln_type: 'file_inclusion',
          name: '本地文件包含载荷规则',
          description: '用于检测本地文件包含(LFI)漏洞的路径遍历载荷',
          rule_content: JSON.stringify({
            subType: 'lfi',
            payloads: payloads
          })
        };

        console.log("准备保存本地文件包含规则:", ruleData);

        if (this.lfiRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.lfiRuleId, ruleData);
          ElMessage.success('本地文件包含规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.lfiRuleId = response.id;
          ElMessage.success('本地文件包含规则创建成功');
        }

        // 更新显示
        this.lfiPayloads = payloads;
        this.isEditingLfi = false;
      } catch (error) {
        console.error('保存本地文件包含规则失败', error);
        ElMessage.error('保存本地文件包含规则失败');
      }
    },

    async saveRfiPayloads() {
      try {
        // 处理文本框中的内容，分割为载荷数组
        const payloads = this.rfiPayloadsText
          .split('\n')
          .map(line => line.trim())
          .filter(line => line);

        // 准备规则数据
        const ruleData = {
          vuln_type: 'file_inclusion',
          name: '远程文件包含载荷规则',
          description: '用于检测远程文件包含(RFI)漏洞的URL载荷',
          rule_content: JSON.stringify({
            subType: 'rfi',
            payloads: payloads
          })
        };

        console.log("准备保存远程文件包含规则:", ruleData);

        if (this.rfiRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.rfiRuleId, ruleData);
          ElMessage.success('远程文件包含规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.rfiRuleId = response.id;
          ElMessage.success('远程文件包含规则创建成功');
        }

        // 更新显示
        this.rfiPayloads = payloads;
        this.isEditingRfi = false;
      } catch (error) {
        console.error('保存远程文件包含规则失败', error);
        ElMessage.error('保存远程文件包含规则失败');
      }
    },

    async saveMatchPatterns() {
      try {
        // 处理文本框中的内容，解析为JSON对象
        let patterns;
        try {
          patterns = JSON.parse(this.filePatternsText);
          // 验证是否为对象
          if (typeof patterns !== 'object' || Array.isArray(patterns) || patterns === null) {
            throw new Error("必须是JSON对象格式");
          }
        } catch (e) {
          ElMessage.error('文件包含匹配模式必须是有效的JSON对象格式');
          return;
        }

        // 准备规则数据
        const ruleData = {
          vuln_type: 'file_inclusion',
          name: '文件包含匹配模式规则',
          description: '用于检测文件包含成功的匹配模式',
          rule_content: JSON.stringify({
            subType: 'patterns',
            patterns: patterns
          })
        };

        console.log("准备保存文件包含匹配模式规则:", ruleData);

        if (this.patternsRuleId) {
          // 如果已有规则，则更新
          await rulesAPI.updateVulnScanRule(this.patternsRuleId, ruleData);
          ElMessage.success('文件包含匹配模式规则更新成功');
        } else {
          // 如果没有规则，则创建
          const response = await rulesAPI.createVulnScanRule(ruleData);
          this.patternsRuleId = response.id;
          ElMessage.success('文件包含匹配模式规则创建成功');
        }

        // 更新显示
        this.filePatterns = patterns;
        this.isEditingPatterns = false;
      } catch (error) {
        console.error('保存文件包含匹配模式规则失败', error);
        ElMessage.error('保存文件包含匹配模式规则失败');
      }
    }
  }
};
</script>

<style scoped>
.fileinclusion-rules {
  margin-bottom: 30px;
}

.fileinclusion-rules h3 {
  margin-bottom: 15px;
  font-size: 18px;
  color: #303133;
  padding-left: 10px;
  border-left: 4px solid #409EFF;
}

.rules-container {
  background-color: #f5f7fa;
  border-radius: 4px;
  padding: 16px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
}

.rule-section {
  margin-bottom: 20px;
  padding-bottom: 20px;
  border-bottom: 1px solid #e6e6e6;
}

.rule-section:last-child {
  margin-bottom: 0;
  padding-bottom: 0;
  border-bottom: none;
}

.rules-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.rule-title {
  font-size: 16px;
  font-weight: bold;
  margin-right: 10px;
  color: #303133;
}

.rule-desc {
  font-size: 12px;
  color: #909399;
}

.rules-content {
  min-height: 100px;
}

.payloads-list {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  min-height: 50px;
}

.payload-item {
  background-color: #ecf5ff;
  color: #409eff;
  padding: 5px 10px;
  border-radius: 4px;
  font-family: monospace;
}

.pattern-list {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.pattern-item {
  font-family: monospace;
  color: #606266;
}

.no-payload, .no-patterns {
  color: #909399;
  font-style: italic;
}

.payloads-edit, .patterns-edit {
  margin-top: 10px;
}

.context-edit-hint {
  font-size: 14px;
  margin-bottom: 10px;
  color: #606266;
}

.hint {
  margin-top: 5px;
  font-size: 12px;
  color: #909399;
}

.loading-state {
  padding: 20px 0;
}

.error-state {
  margin: 20px 0;
}
</style>