# 提交材料：awesome-dsh-plugin

本目录是为社区列表 [awesome-dsh-plugin/awesome-dsh-plugin](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin) 准备的投稿素材，不参与插件运行。

## 文件

- `xiongking__dsh-reverse-proxy-gateway.yml` —— 条目文件，PR 时放到对方仓库的 `data/plugins/` 下。
- `PR-BODY.md` —— PR 正文。

## 提交前提（对方 CI 会逐项检查）

| 检查项 | 当前状态 |
|---|---|
| `package.json` 声明 `dsh.bundle.patch` | 已声明 |
| 仓库根有 `cordis.patch.yml` | 已就位 |
| 仓库带 `dsh-plugin` topic | 已加（另有 deepseek-harness、dsh、gateway、remote-access、reverse-proxy） |
| 仓库创建满 1 天 | 已满足（创建于 2026-11-10 22:21 UTC） |
| 只改自己那一条 | 只新增本文件，不动任何既有条目 |

已提交：<https://github.com/awesome-dsh-plugin/awesome-dsh-plugin/pull/17559>（2026-11-21）。

## 提交步骤

```sh
# 1. fork 并克隆
gh repo fork awesome-dsh-plugin/awesome-dsh-plugin --clone
cd awesome-dsh-plugin

# 2. 放入条目文件（文件名必须是 <owner>__<repo>.yml）
mkdir -p data/plugins
cp <本目录>/xiongking__dsh-reverse-proxy-gateway.yml data/plugins/

# 3. 只提交这一个文件，不要手工改 README（README 由脚本生成）
git checkout -b add-dsh-reverse-proxy-gateway
git add data/plugins/xiongking__dsh-reverse-proxy-gateway.yml
git commit -m "Add dsh-reverse-proxy-gateway"
git push -u origin add-dsh-reverse-proxy-gateway

# 4. 开 PR，正文用 PR-BODY.md 的内容
gh pr create --title "Add dsh-reverse-proxy-gateway" --body-file PR-BODY.md
```

CI 通过只是前置条件，最终由维护者阅读仓库后合并。反馈会以 PR 评论给出并打 `held: author` 标签，把改动推到**同一分支**、留一条说明评论即可，无需重开 PR。

## 其他渠道

- **npm**：`name` 未被占用，发布后可免掉源码构建的 `allowBuilds` 授权步骤（可选）。
- **第三方 format-1 索引**（如 dsh-plugin-hub）：硬性要求每个版本带有效 `engines.dsh`，本项目自 0.2.0 起已声明。
- **官方市场**：不存在。官方 `CONTRIBUTING.md` 明确「目前不接受外部 PR」，索引规范也写明「目前没有官方市场，以后可能会增加」。
