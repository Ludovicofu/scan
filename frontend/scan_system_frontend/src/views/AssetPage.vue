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
            {{ scope.row.host }}
          </template>
        </el-table-column>

        <el-table-column
          label="信息收集结果"
          width="120"
          align="center"
        >
          <template #default="scope">
            <el-tag type="info">{{ scope.row.info_count || 0 }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column
          label="漏洞检测结果"
          width="120"
          align="center"
        >
          <template #default="scope">
            <el-tag type="danger">{{ scope.row.vuln_count || 0 }}</el-tag>
          </template>
        </el-table-column>

        <!-- 添加资产备注列 -->
        <el-table-column
          label="资产备注"
          width="200"
        >
          <template #default="scope">
            <span v-if="getFirstNote(scope.row)" class="note-preview">
              {{ truncateNoteText(getFirstNote(scope.row)) }}
            </span>
            <span v-else class="note-empty">暂无备注</span>
          </template>
        </el-table-column>

        <el-table-column
          label="操作"
          width="220"
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
              @click="showNoteDialog(scope.row)"
              type="success"
              size="small"
              plain
            >
              备注
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

            <!-- 无数据提示 -->
            <div v-if="infoResults.length === 0" class="no-data-tip">
              暂无信息收集结果
            </div>
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

            <!-- 无数据提示 -->
            <div v-if="vulnResults.length === 0" class="no-data-tip">
              暂无漏洞检测结果
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="detailDialogVisible = false">关闭</el-button>
        </span>
      </template>
    </el-dialog>

    <!-- 备注编辑对话框 -->
    <el-dialog
      :title="editingNote ? '修改备注' : '添加备注'"
      v-model="noteDialogVisible"
      width="50%"
    >
      <el-form :model="noteForm" ref="noteFormRef" :rules="noteRules">
        <el-form-item label="备注内容" prop="content">
          <el-input
            v-model="noteForm.content"
            type="textarea"
            :rows="5"
            placeholder="请输入备注内容"
          ></el-input>
        </el-form-item>
      </el-form>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="noteDialogVisible = false">取消</el-button>
          <el-button type="primary" @click="saveNote" :loading="noteSaving">保存</el-button>
        </span>
      </template>
    </el-dialog>
  </div>
</template>

<script>
import { assetAPI } from '@/services/api';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Search, Edit, Delete, Plus } from '@element-plus/icons-vue';

export default {
  name: 'AssetPage',
  components: {},
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

      // 备注对话框相关
      noteDialogVisible: false,
      noteSaving: false,
      editingNote: null,
      noteForm: {
        assetId: null,
        content: ''
      },
      noteRules: {
        content: [
          { required: true, message: '请输入备注内容', trigger: 'blur' },
          { min: 1, max: 500, message: '备注长度在1-500个字符之间', trigger: 'blur' }
        ]
      },

      // 图标
      Search,
      Edit,
      Delete,
      Plus
    };
  },
  created() {
    this.fetchAssets();
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

        const response = await assetAPI.getAssets(params);
        this.assets = response.results || [];
        this.totalAssets = response.count || 0;

        // 加载每个资产的备注
        for (const asset of this.assets) {
          this.loadAssetNotes(asset.id);
        }
      } catch (error) {
        console.error('获取资产列表失败', error);
        ElMessage.error('获取资产列表失败');
      } finally {
        this.loading = false;
      }
    },

    // 获取资产的第一条备注
    getFirstNote(asset) {
      if (!asset || !asset.notes || asset.notes.length === 0) {
        return null;
      }
      return asset.notes[0].content;
    },

    // 截断备注文本
    truncateNoteText(text) {
      if (!text) return '';
      return text.length > 15 ? text.substring(0, 15) + '...' : text;
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

    // 显示资产详情
    async showDetail(asset) {
      this.selectedAsset = asset;
      this.detailDialogVisible = true;
      this.activeDetailTab = 'info';

      // 加载详情数据
      await this.loadDetailData(asset.id);

      // 获取资产备注
      await this.fetchAssetNotes(asset.id);
    },

    // 加载详情数据
    async loadDetailData(assetId) {
      this.detailLoading = true;
      try {
        // 获取资产详情
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

    // 加载资产备注（用于列表中显示）
    async loadAssetNotes(assetId) {
      try {
        const response = await assetAPI.getAssetNotes(assetId);
        // 将备注添加到资产对象中
        const asset = this.assets.find(a => a.id === assetId);
        if (asset) {
          asset.notes = response.results || [];
        }
      } catch (error) {
        console.error(`加载资产${assetId}的备注失败`, error);
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

    // 显示备注对话框
    showNoteDialog(asset) {
      this.selectedAsset = asset;
      this.editingNote = null;
      this.noteForm = {
        assetId: asset.id,
        content: ''
      };
      this.noteDialogVisible = true;
    },

    // 编辑备注
    editNote(note) {
      this.editingNote = note;
      this.noteForm = {
        assetId: this.selectedAsset.id,
        content: note.content
      };
      this.noteDialogVisible = true;
    },

    // 保存备注
    async saveNote() {
      try {
        // 表单验证
        await this.$refs.noteFormRef.validate();

        this.noteSaving = true;

        if (this.editingNote) {
          // 更新备注
          await assetAPI.updateAssetNote(this.editingNote.id, {
            content: this.noteForm.content
          });
          ElMessage.success('备注更新成功');
        } else {
          // 添加新备注
          await assetAPI.createAssetNote(this.noteForm.assetId, {
            content: this.noteForm.content,
            asset: this.noteForm.assetId
          });
          ElMessage.success('备注添加成功');
        }

        // 关闭对话框
        this.noteDialogVisible = false;

        // 刷新备注列表
        await this.fetchAssetNotes(this.selectedAsset.id);

        // 更新资产的备注
        await this.loadAssetNotes(this.selectedAsset.id);

      } catch (error) {
        if (error !== false) { // 非表单验证错误
          console.error('保存备注失败', error);
          ElMessage.error('保存备注失败');
        }
      } finally {
        this.noteSaving = false;
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

.note-preview {
  color: #606266;
  font-size: 13px;
}

.note-empty {
  color: #909399;
  font-size: 13px;
  font-style: italic;
}

.no-data-tip {
  text-align: center;
  color: #909399;
  padding: 30px 0;
  font-size: 14px;
}
</style>