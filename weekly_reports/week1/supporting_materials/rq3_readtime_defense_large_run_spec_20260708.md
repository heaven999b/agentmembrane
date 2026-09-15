# RQ3 读取侧防御大跑说明（2026-07-08）

这次大跑只回答一个问题：

> 把“官方政策优先于团队惯例”的读取侧防御放进记忆以后，能不能稳定减少错误行动？

---

## 1. 固定口径

这次不再混别的变量，只固定这一套：

| 维度 | 固定设置 |
| --- | --- |
| 题库 | `benchmarks/safety/stealthy_poison_suite_v1.json` |
| 注入政策 | `on` |
| poison framing | `convention` |
| query mode | `neutral` |
| 模型 | `gpt-4.1-mini` |
| defense | `off` vs `on` |
| backend | `prompt_only` vs `tiermem` |
| TierMem 深度 | `N=0,1,2` |
| seeds | `11,17,23,29,31` |

所以完整矩阵是：

- `prompt_only`: `5 seeds × 2 defense = 10 runs`
- `tiermem`: `5 seeds × 2 defense = 10 runs`
  - 每个 run 内含 `N=0/1/2`

总共：

- `20` 个 report

---

## 2. 为什么先跑这条

因为这条是现在唯一还有机会从“苗头”变成“站得住正结果”的线。

当前已知小样本信号：

| 条件 | 错误行动率 |
| --- | ---: |
| 无防御 | `28/30 = 0.933` |
| 有防御 | `23/30 = 0.767` |

而且配对翻转是：

- `5` 条从错变对
- `0` 条从对变错

这说明方向是对的，只是还不够大。

---

## 3. 新脚本

### 3.1 批量启动

脚本：

- [run_rq3_readtime_defense_matrix.py](https://github.com/heaven999b/memory_consolidation_small_pilot/blob/main/run_rq3_readtime_defense_matrix.py)

作用：

- 自动生成全部矩阵任务
- 自动加载 `.env.v3`
- 自动写 manifest
- 支持 `--skip-existing` 断点续跑

默认 run tag：

- `rq3_readtime_large_20260708`

### 3.2 自动汇总

脚本：

- [summarize_rq3_readtime_defense_matrix.py](https://github.com/heaven999b/memory_consolidation_small_pilot/blob/main/summarize_rq3_readtime_defense_matrix.py)

作用：

- 读 manifest
- 汇总每个 seed / backend / pass 的错误行动率
- 做 `off` vs `on` 的逐题配对翻转统计

---

## 4. 怎么跑

### 4.1 正式启动

```bash
cd "${MEMORY_PROJECT_ROOT}"
.venv_tiermem_v2/bin/python run_rq3_readtime_defense_matrix.py --skip-existing
```

### 4.2 如果中途断了，继续跑

```bash
cd "${MEMORY_PROJECT_ROOT}"
.venv_tiermem_v2/bin/python run_rq3_readtime_defense_matrix.py --skip-existing
```

因为 report id 固定，已经完成的会自动跳过。

### 4.3 跑完后汇总

```bash
cd "${MEMORY_PROJECT_ROOT}"
python3 summarize_rq3_readtime_defense_matrix.py --run-tag rq3_readtime_large_20260708
```

---

## 5. 主要输出位置

### 5.1 运行清单

- `outputs/safety/rq3_readtime_large_20260708_manifest.json`

### 5.2 原始 report

命名规则：

- `outputs/safety/rq3_readtime_large_20260708_po_off_seed11.json`
- `outputs/safety/rq3_readtime_large_20260708_po_on_seed11.json`
- `outputs/safety/rq3_readtime_large_20260708_tm_off_seed11.json`
- `outputs/safety/rq3_readtime_large_20260708_tm_on_seed11.json`

其他 seed 同理。

### 5.3 汇总文件

- `state/rq3_readtime_large_20260708_condition_summary.csv`
- `state/rq3_readtime_large_20260708_paired_summary.csv`
- `state/rq3_readtime_large_20260708_summary.md`

---

## 6. 跑完以后最想看的表

最关键的是这张：

| backend | pass | off mean | on mean | delta | better flips | worse flips |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |

如果你看到：

- `on mean` 稳定低于 `off mean`
- `better flips` 明显多于 `worse flips`
- 这种差距不只出现在一个 seed

那这条线就值得继续写成主结果。

如果你看到：

- 一换 seed 就消失
- `better` 和 `worse` 差不多
- `tiermem` 和 `prompt_only` 都没有一致方向

那就说明这条防御也不够稳，不该再押太多。
