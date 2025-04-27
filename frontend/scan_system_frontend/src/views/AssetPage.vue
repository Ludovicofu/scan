<template>
  <div class="asset-page">
    <h1>资产管理</h1>

    <!-- 搜索和过滤 -->
    <div class="filter-section">
      <el-form :inline="true" class="filter-form">
        <el-form-item label="搜索资产">
          <el-input
            v-model="searchQuery"
            placeholder="输入主机名/IP"
            clearable
            @input="handleSearch"
          >
            <template #append>
              <el-button :icon="Search" @click="handleSearch"></el-button>
            </template>
          </el-input>
        </el-form-item>

        <el-form-item label="标签">
          <el-select
            v-model="selectedTag"
            placeholder="选择标签"
            clearable
            @change="handleTagChange"
          >
            <el-option
              v-for="tag in tags"
              :key="tag.id"
              :label="tag.name"
              :value="tag.id"
            >
              <span :style="{color: tag.color}">● </span>
              <span>{{ tag.name }}</span>
            </el-option>
          </el-select>
        </el-form-item>

        <el-form-item label="分组">
          <el-select
            v-model="selectedGroup"
            placeholder="选择分组"
            clearable
            @change="handleGroupChange"
          >
            <el-option
              v-for="group in groups"
              :key="group.id"
              :label="group.name"
              :value="group.id"
            ></el-option>
          </el-select>
        </el-form-item>
      </el-form>
    </div>

    <!-- 统计卡片 -->
    <div class="stats-section" v-if="showStatistics">
      <el-row :gutter="20">
        <el-col :span="6">
          <el-card class="stats-card">
            <div class="stats-content">
              <div class="stats-number">{{ statistics.total_assets }}</div>
              <div class="stats-label">资产总数</div>
            </div>
          </el-card>
        </el-col>
        <el-col :span="6">
          <el-card class="stats-card">
            <div class="stats-content">
              <div class="stats-number">{{ statistics.recent_assets }}</div>
              <div class="stats-label">最近新增资产</div>
            </div>
          </el-card>
        </el-col>
        <el-col :span="6">
          <el-card class="stats-card">
            <div class="stats-content">
              <div class="stats-number">{{ statistics.vuln_assets }}</div>
              <div class="stats-label">存在漏洞的资产</div>
            </div>
          </el-card>
        </el-col>
        <el-col :span="6">
          <el-card class="stats-card">
            <div class="stats-content">
              <div class="stats-number">{{ statistics.high_risk_assets }}</div>
              <div class="stats-label">高危资产</div>
            </div>
          </el-card>
        </el-col>
      </el-row>
    </div>

    <!-- 资产列表 -->
    <div class="asset-list">
      <el-table
        v-loading="loading"
        :data="assets"
        border
        style="width: 100%"
      >
        <el-table-column
          type="index"
          label="序号"
          width="60"
        ></el-table-column>

        <el-table-column
          prop="last_seen"
          label="日期"
          width="180"
          sortable
        >
          <template #default="scope">
            {{ formatDate(scope.row.last_seen) }}
          </template>
        </el-table-column>

        <el-table-column
          prop="host"
          label="资产"
          width="220"
        >
          <template #default="scope">
            <div>
              {{ scope.row.host }}
              <span v-if="scope.row.tags && scope.row.tags.length > 0" class="asset-tags">
                <el-tag
                  v-for="tag in scope.row.tags"
                  :key="tag.id"
                  :color="tag.color"
                  effect="plain"
                  size="small"
                  class="tag-item"
                >
                  {{ tag.name }}
                </el-tag>
              </span>
            </div>
          </template>
        </el-table-column>

        <el-table-column
          label="信息收集结果"
          width="150"
          align="center"
        >
          <template #default="scope">
            <el-tag type="info">{{ scope.row.info_count || 0 }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column
          label="漏洞检测结果"
          width="150"
          align="center"
        >
          <template #default="scope">
            <el-tag type="danger">{{ scope.row.vuln_count || 0 }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column
          label="操作"
          width="180"
          fixed="right"
        >
          <template #default="scope">
            <el-button
              @click="showDetail(scope.row)"
              type="primary"
              size="small"
              plain
            >
              详情
            </el-button>
            <el-button
              @click="deleteAsset(scope.row.id)"
              type="danger"
              size="small"
              plain
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <div class="pagination">
        <el-pagination
          @size-change="handleSizeChange"
          @current-change="handlePageChange"
          v-model:current-page="currentPage"
          :page-sizes="[10, 20, 50, 100]"
          v-model:page-size="pageSize"
          layout="total, sizes, prev, pager, next, jumper"
          :total="totalAssets"
        ></el-pagination>
      </div>
    </div>

    <!-- 资产详情对话框 -->
    <el-dialog
      title="资产详情"
      v-model="detailDialogVisible"
      width="80%"
    >
      <div v-if="selectedAsset" class="asset-detail">
        <h2>{{ selectedAsset.host }}</h2>
        <p>
          <strong>首次发现时间：</strong> {{ formatDate(selectedAsset.first_seen) }}<br>
          <strong>最后发现时间：</strong> {{ formatDate(selectedAsset.last_seen) }}
        </p>

        <!-- 标签管理 -->
        <div class="asset-tags-section">
          <h3>标签管理</h3>
          <div class="tags-container">
            <el-tag
              v-for="tag in selectedAsset.tags"
              :key="tag.id"
              :color="tag.color"
              effect="plain"
              closable
              @close="removeTagFromAsset(selectedAsset.id, tag.id)"
              class="asset-tag"
            >
              {{ tag.name }}
            </el-tag>

            <el-dropdown @command="addTagToAsset(selectedAsset.id, $event)" trigger="click">
              <el-button size="small" plain>添加标签</el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item
                    v-for="tag in availableTags"
                    :key="tag.id"
                    :command="tag.id"
                  >
                    <span :style="{color: tag.color}">● </span>
                    {{ tag.name }}
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </div>
        </div>

        <!-- 资产备注 -->
        <div class="asset-notes-section">
          <h3>资产备注</h3>
          <div class="notes-container">
            <div v-for="note in assetNotes" :key="note.id" class="note-item">
              <div class="note-content">{{ note.content }}</div>
              <div class="note-time">{{ formatDate(note.created_at) }}</div>
              <el-button type="danger" size="small" plain icon="Delete" @click="deleteNote(note.id)" class="note-delete-btn"></el-button>
            </div>

            <div class="add-note">
              <el-input
                v-model="newNoteContent"
                type="textarea"
                :rows="3"
                placeholder="添加备注..."
              ></el-input>
              <el-button type="primary" @click="addNote(selectedAsset.id)" :disabled="!newNoteContent">添加备注</el-button>
            </div>
          </div>
        </div>

        <!-- 详情标签页 -->
        <el-tabs v-model="activeDetailTab">
          <el-tab-pane label="信息收集结果" name="info">
            <el-table
              v-loading="detailLoading"
              :data="infoResults"
              border
              style="width: 100%"
            >
              <el-table-column
                type="index"
                label="序号"
                width="60"
              ></el-table-column>

              <el-table-column
                prop="scan_date"
                label="日期"
                width="180"
                sortable
              >
                <template #default="scope">
                  {{ formatDate(scope.row.scan_date) }}
                </template>
              </el-table-column>

              <el-table-column
                prop="module_display"
                label="模块"
                width="150"
              ></el-table-column>

              <el-table-column
                prop="description"
                label="描述"
                width="200"
              ></el-table-column>

              <el-table-column
                prop="match_value"
                label="匹配值"
                show-overflow-tooltip
              ></el-table-column>

              <el-table-column
                prop="scan_type_display"
                label="扫描类型"
                width="120"
              ></el-table-column>
            </el-table>
          </el-tab-pane>

          <el-tab-pane label="漏洞检测结果" name="vuln">
            <el-table
              v-loading="detailLoading"
              :data="vulnResults"
              border
              style="width: 100%"
            >
              <el-table-column
                type="index"
                label="序号"
                width="60"
              ></el-table-column>

              <el-table-column
                prop="scan_date"
                label="日期"
                width="180"
                sortable
              >
                <template #default="scope">
                  {{ formatDate(scope.row.scan_date) }}
                </template>
              </el-table-column>

              <el-table-column
                prop="vuln_type_display"
                label="漏洞类型"
                width="150"
              ></el-table-column>

              <el-table-column
                prop="name"
                label="漏洞名称"
                width="200"
              ></el-table-column>

              <el-table-column
                prop="severity_display"
                label="严重程度"
                width="100"
              >
                <template #default="scope">
                  <el-tag
                    :type="getSeverityType(scope.row.severity)"
                    size="small"
                  >
                    {{ scope.row.severity_display }}
                  </el-tag>
                </template>
              </el-table-column>

              <el-table-column
                prop="url"
                label="URL"
                show-overflow-tooltip
              ></el-table-column>
            </el-table>
          </el-tab-pane>
        </el-tabs>
      </div>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="detailDialogVisible = false">关闭</el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script>
import { assetAPI } from '@/services/api';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Search } from '@element-plus/icons-vue';

export default {
  name: 'AssetPage',
  components: {
    Search
  },
  data() {
    return {
      // 资产列表数据
      loading: false,
      assets: [],
      totalAssets: 0,
      currentPage: 1,
      pageSize: 10,

      // 搜索和过滤
      searchQuery: '',
      selectedTag: null,
      selectedGroup: null,

      // 标签和分组数据
      tags: [],
      groups: [],

      // 统计数据
      statistics: {
        total_assets: 0,
        recent_assets: 0,
        vuln_assets: 0,
        high_risk_assets: 0
      },
      showStatistics: true,

      // 详情对话框
      detailDialogVisible: false,
      selectedAsset: null,
      activeDetailTab: 'info',
      detailLoading: false,
      infoResults: [],
      vulnResults: [],

      // 资产备注相关
      assetNotes: [],
      newNoteContent: '',

      // 可用标签（排除已经添加的）
      availableTags: []
    };
  },
  created() {
    this.fetchAssets();
    this.fetchTags();
    this.fetchGroups();
    this.fetchStatistics();
  },
  methods: {
    // 获取资产列表
    async fetchAssets() {
      this.loading = true;
      try {
        const params = {
          page: this.currentPage,
          page_size: this.pageSize,
          search: this.searchQuery || undefined
        };

        // 添加标签过滤
        if (this.selectedTag) {
          params.tag = this.selectedTag;
        }

        // 添加分组过滤
        if (this.selectedGroup) {
          params.group = this.selectedGroup;
        }

        const response = await assetAPI.getAssets(params);
        this.assets = response.results || [];
        this.totalAssets = response.count || 0;
      } catch (error) {
        console.error('获取资产列表失败', error);
        ElMessage.error('获取资产列表失败');
      } finally {
        this.loading = false;
      }
    },

    // 获取标签列表
    async fetchTags() {
      try {
        const response = await assetAPI.getTags();
        this.tags = response.results || [];
      } catch (error) {
        console.error('获取标签列表失败', error);
      }
    },

    // 获取分组列表
    async fetchGroups() {
      try {
        const response = await assetAPI.getGroups();
        this.groups = response.results || [];
      } catch (error) {
        console.error('获取分组列表失败', error);
      }
    },

    // 获取统计数据
    async fetchStatistics() {
      try {
        const response = await assetAPI.getAssetStatistics();
        this.statistics = response;
      } catch (error) {
        console.error('获取统计数据失败', error);
      }
    },

    // 搜索和过滤处理
    handleSearch() {
      this.currentPage = 1; // 重置页码
      this.fetchAssets();
    },

    handleTagChange() {
      this.currentPage = 1;
      this.fetchAssets();
    },

    handleGroupChange() {
      this.currentPage = 1;
      this.fetchAssets();
    },

    // 显示资产详情
    async showDetail(asset) {
      this.selectedAsset = asset;
      this.detailDialogVisible = true;
      this.activeDetailTab = 'info';

      // 加载详情数据
      await this.loadDetailData(asset.id);

      // 获取资产备注
      await this.fetchAssetNotes(asset.id);

      // 更新可用标签列表
      this.updateAvailableTags();
    },

    // 加载详情数据
    async loadDetailData(assetId) {
      this.detailLoading = true;
      try {
        // 获取资产详情（包含标签）
        const assetDetail = await assetAPI.getAssetDetail(assetId);
        this.selectedAsset = assetDetail;

        // 获取信息收集结果
        const infoResponse = await assetAPI.getAssetInfoResults(assetId);
        this.infoResults = infoResponse.results || [];

        // 获取漏洞检测结果
        const vulnResponse = await assetAPI.getAssetVulnResults(assetId);
        this.vulnResults = vulnResponse.results || [];
      } catch (error) {
        console.error('获取资产详情数据失败', error);
        ElMessage.error('获取资产详情数据失败');
      } finally {
        this.detailLoading = false;
      }
    },

    // 获取资产备注
    async fetchAssetNotes(assetId) {
      try {
        const response = await assetAPI.getAssetNotes(assetId);
        this.assetNotes = response.results || [];
      } catch (error) {
        console.error('获取资产备注失败', error);
        ElMessage.error('获取资产备注失败');
      }
    },

    // 添加资产备注
    async addNote(assetId) {
      if (!this.newNoteContent) return;

      try {
        await assetAPI.createAssetNote(assetId, { content: this.newNoteContent });
        ElMessage.success('添加备注成功');

        // 刷新备注列表
        await this.fetchAssetNotes(assetId);
        this.newNoteContent = ''; // 清空输入
      } catch (error) {
        console.error('添加备注失败', error);
        ElMessage.error('添加备注失败');
      }
    },

    // 删除资产备注
    async deleteNote(noteId) {
      try {
        await ElMessageBox.confirm('确认删除此备注？', '提示', {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
        });

        await assetAPI.deleteAssetNote(noteId);
        ElMessage.success('删除备注成功');

        // 刷新备注列表
        if (this.selectedAsset) {
          await this.fetchAssetNotes(this.selectedAsset.id);
        }
      } catch (error) {
        if (error !== 'cancel') {
          console.error('删除备注失败', error);
          ElMessage.error('删除备注失败');
        }
      }
    },

    // 更新可用标签列表
    updateAvailableTags() {
      if (!this.selectedAsset || !this.selectedAsset.tags) return;

      // 过滤出未添加到当前资产的标签
      const currentTagIds = this.selectedAsset.tags.map(tag => tag.id);
      this.availableTags = this.tags.filter(tag => !currentTagIds.includes(tag.id));
    },

    // 添加标签到资产
    async addTagToAsset(assetId, tagId) {
      try {
        await assetAPI.addTagToAsset(assetId, tagId);
        ElMessage.success('添加标签成功');

        // 刷新资产详情
        await this.loadDetailData(assetId);
        this.updateAvailableTags();
      } catch (error) {
        console.error('添加标签失败', error);
        ElMessage.error('添加标签失败');
      }
    },

    // 从资产移除标签
    async removeTagFromAsset(assetId, tagId) {
      try {
        await assetAPI.removeTagFromAsset(assetId, tagId);
        ElMessage.success('移除标签成功');

        // 刷新资产详情
        await this.loadDetailData(assetId);
        this.updateAvailableTags();
      } catch (error) {
        console.error('移除标签失败', error);
        ElMessage.error('移除标签失败');
      }
    },

    // 删除资产
    async deleteAsset(assetId) {
      try {
        await ElMessageBox.confirm('确认删除此资产？此操作将同时删除与此资产相关的所有信息收集结果和漏洞检测结果。', '提示', {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
        });

        await assetAPI.deleteAsset(assetId);
        ElMessage.success('删除资产成功');

        // 刷新资产列表
        this.fetchAssets();
        // 刷新统计数据
        this.fetchStatistics();
      } catch (error) {
        if (error !== 'cancel') {
          console.error('删除资产失败', error);
          ElMessage.error('删除资产失败');
        }
      }
    },

    // 分页处理
    handleSizeChange(val) {
      this.pageSize = val;
      this.fetchAssets();
    },

    handlePageChange(val) {
      this.currentPage = val;
      this.fetchAssets();
    },

    // 格式化日期
    formatDate(dateString) {
      if (!dateString) return '';
      const date = new Date(dateString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
    },

    // 获取漏洞严重程度对应的样式类型
    getSeverityType(severity) {
      const severityMap = {
        'high': 'danger',
        'medium': 'warning',
        'low': 'info',
        'info': 'success'
      };
      return severityMap[severity] || 'info';
    }
  }
};
</script>

<style scoped>
.asset-page {
  padding: 20px;
}

h1 {
  margin-bottom: 20px;
  font-size: 24px;
  color: #303133;
}

.filter-section {
  margin-bottom: 20px;
  background-color: #f5f7fa;
  padding: 15px;
  border-radius: 4px;
}

.stats-section {
  margin-bottom: 20px;
}

.stats-card {
  height: 120px;
  text-align: center;
  display: flex;
  align-items: center;
  justify-content: center;
}

.stats-content {
  width: 100%;
}

.stats-number {
  font-size: 32px;
  font-weight: bold;
  color: #409EFF;
  margin-bottom: 8px;
}

.stats-label {
  font-size: 14px;
  color: #606266;
}

.asset-list {
  margin-bottom: 20px;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.asset-detail h2 {
  color: #303133;
  font-size: 20px;
  margin-bottom: 10px;
}

.asset-detail p {
  color: #606266;
  margin-bottom: 20px;
}

.asset-detail h3 {
  font-size: 16px;
  color: #303133;
  margin-top: 20px;
  margin-bottom: 15px;
  border-left: 4px solid #409EFF;
  padding-left: 10px;
}

.asset-tags-section, .asset-notes-section {
  background-color: #f5f7fa;
  padding: 15px;
  border-radius: 4px;
  margin-bottom: 20px;
}

.tags-container {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
}

.asset-tag {
  margin-right: 5px;
}

.notes-container {
  margin-bottom: 20px;
}

.note-item {
  display: flex;
  padding: 10px;
  border-bottom: 1px solid #ebeef5;
  position: relative;
}

.note-content {
  flex: 1;
}

.note-time {
  color: #909399;
  font-size: 12px;
  margin-left: 15px;
  min-width: 120px;
}

.note-delete-btn {
  visibility: hidden;
  position: absolute;
  right: 0;
  top: 50%;
  transform: translateY(-50%);
}

.note-item:hover .note-delete-btn {
  visibility: visible;
}

.add-note {
  margin-top: 15px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.add-note .el-button {
  align-self: flex-end;
}

.asset-tags {
  margin-left: 10px;
}

.tag-item {
  margin-right: 5px;
}