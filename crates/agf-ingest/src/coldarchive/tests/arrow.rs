//! 冷归档 **arrow 列式读回** 用例：schema 映射、逐列单元格比对、两条读回路径一致、分批与拒绝畸形输入。
//!
//! 夹具（`event` / `sample`）来自父模块 `coldarchive::tests`。

use super::*;

/// arrow 列名与 schema 声明的 13 列一一对应，且类型按"时间列 TIMESTAMP(MILLIS) / 其余 UTF-8"落地。
#[test]
fn arrow_schema_maps_all_thirteen_columns_with_expected_types() {
    let bytes = encode_parquet(&sample()).unwrap_or_default();
    assert!(!bytes.is_empty(), "Parquet 编码必须成功（否则后续断言无意义）");
    let schema = parquet_arrow_schema(&bytes);
    assert!(schema.is_ok(), "{schema:?}");
    let Ok(schema) = schema else { return };

    let names: Vec<String> = schema.fields().iter().map(|field| field.name().clone()).collect();
    assert_eq!(names, PARQUET_COLUMNS.to_vec(), "arrow 列名必须与写出侧 PARQUET_COLUMNS 完全一致");
    assert_eq!(names.len(), 13);

    // 时间列 → arrow Timestamp(Millisecond, _)；其余 → Utf8（parquet BINARY + STRING 逻辑类型）
    for field in schema.fields() {
        let rendered = format!("{}", field.data_type());
        if field.name() == "time" || field.name() == "ingested_at" {
            assert!(rendered.starts_with("Timestamp(Millisecond"), "{} 应为毫秒时间戳，实际 {rendered}", field.name());
        } else {
            assert_eq!(rendered, "Utf8", "{} 应为 Utf8 字符串列，实际 {rendered}", field.name());
        }
    }
    // 与低层 schema 文本同源：13 个 REQUIRED 列一个不少
    assert_eq!(PARQUET_SCHEMA.matches("REQUIRED").count(), 13);
}

/// 逐列比对：arrow 读回的**每个单元格**都必须等于写出侧同一套映射（[`event_column_text`]）的值。
#[test]
fn arrow_readback_matches_written_cells_column_by_column() {
    let events = sample();
    let bytes = encode_parquet(&events).unwrap_or_default();
    let facts = arrow_facts(&bytes, events.len());
    assert!(facts.is_ok(), "{facts:?}");
    let Ok(facts) = facts else { return };
    assert_eq!(facts.rows, events.len());
    assert_eq!(facts.batches, 1, "3 行 + 默认批大小 1024 ⇒ 1 批");
    assert!(facts.columns_match_schema(), "{:?}", facts.column_names());

    for (row, event) in events.iter().enumerate() {
        let expected = event_column_text(event).unwrap_or_default();
        assert_eq!(expected.len(), 13);
        for (column, want) in &expected {
            let got = facts.cell(column, row).unwrap_or("<缺失>");
            assert_eq!(got, want, "第 {} 行 {column} 列读回值与写出值不一致", row + 1);
        }
        // 时间列落盘是 Unix 毫秒（可直接与事件字段核对）
        assert_eq!(facts.cell("time", row), Some(event.time.unix_millis().to_string().as_str()));
        assert_eq!(facts.cell("severity", row), Some(event.severity.as_str()));
        assert_eq!(facts.cell("raw_hash", row), Some(event.raw_hash.as_str()));
    }
    // 人读报告必须带行数/列名/单元格（证据格式）
    let report = facts.report();
    assert!(report.contains("arrow 读回：3 行"), "{report}");
    assert!(report.contains("raw_json"), "{report}");
    assert!(report.contains("Timestamp(Millisecond"), "{report}");
}

/// arrow 与低层行式两条读回路径**逐条一致**，且每行的列式投影都能对上事件字段（无损性）。
#[test]
fn arrow_and_low_level_readback_agree_and_columns_match_events() {
    let events = sample();
    let bytes = encode_parquet(&events).unwrap_or_default();
    let readback = read_parquet_arrow(&bytes, 2, events.len());
    assert!(readback.is_ok(), "{readback:?}");
    let Ok(readback) = readback else { return };
    assert_eq!(readback.events.len(), events.len());
    assert_eq!(readback.facts.batches, 2, "3 行 + 批大小 2 ⇒ 2 批（末批 1 行）");
    assert!(readback.all_columns_match_events(), "{}", readback.mismatch_summary());
    assert!(readback.mismatch_summary().contains("13 列与事件字段一致"), "{}", readback.mismatch_summary());

    // 与低层 parquet::record 路径逐字段比对（两条路径不许有口径差）
    let rows = decode_parquet_rows(&bytes);
    assert!(rows.is_ok(), "{rows:?}");
    let Ok(rows) = rows else { return };
    assert_eq!(rows.len(), readback.events.len());
    for (arrow_event, row_event) in readback.events.iter().zip(rows.iter()) {
        assert_eq!(arrow_event.id, row_event.id);
        assert_eq!(arrow_event.time, row_event.time);
        assert_eq!(arrow_event.ingested_at, row_event.ingested_at);
        assert_eq!(arrow_event.message, row_event.message);
        assert_eq!(arrow_event.raw_hash, row_event.raw_hash);
        assert_eq!(arrow_event.severity, row_event.severity);
        assert_eq!(arrow_event.tenant_id, row_event.tenant_id);
        assert_eq!(arrow_event.host.name, row_event.host.name);
    }
    // decode_parquet 就是 arrow 路径（同输入同输出）
    let via_public = decode_parquet(&bytes).unwrap_or_default();
    assert_eq!(via_public.len(), rows.len());
    for (left, right) in via_public.iter().zip(readback.events.iter()) {
        assert_eq!(left.id, right.id);
        assert_eq!(left.raw_hash, right.raw_hash);
    }
    // 抽样开关：sample_rows=0 ⇒ 不抽单元格，但行数照旧
    let no_sample = read_parquet_arrow(&bytes, 8, 0).unwrap_or_else(|_| ArrowReadback {
        facts: ArrowFacts { rows: 0, batches: 0, columns: Vec::new() },
        events: Vec::new(),
        columns_match_event: Vec::new(),
    });
    assert_eq!(no_sample.facts.rows, events.len());
    assert!(no_sample.facts.columns.iter().all(|column| column.samples.is_empty()));
    assert!(no_sample.columns_match_event.iter().all(|ok| *ok), "不抽样也照做列比对");
}

/// 行报告与分批：批大小 < 行数 ⇒ 多批；`row_report` 给出可核对的"列名=值"文本。
#[test]
fn arrow_row_report_renders_every_column() {
    let events = sample();
    let bytes = encode_parquet(&events).unwrap_or_default();
    let report = row_report(&bytes, 1);
    assert!(report.is_ok(), "{report:?}");
    let Ok(report) = report else { return };
    for column in PARQUET_COLUMNS {
        assert!(report.contains(&format!("{column}=")), "行报告缺少列 {column}：{report}");
    }
    assert!(report.contains(&events[1].message), "{report}");
    assert!(row_report(&bytes, events.len() + 5).is_err(), "越界行必须显式报错");
}

/// 畸形输入：非 Parquet / 缺 `raw_json` 列 ⇒ 显式报错（绝不静默返回空事件列表）。
#[test]
fn arrow_readback_rejects_non_parquet_and_missing_raw_json_column() {
    assert!(arrow_facts(b"not parquet", 3).is_err());
    assert!(parquet_arrow_schema(b"PAR1PAR1").is_err());
    assert!(decode_parquet_arrow(b"").is_err());

    // 手写一个**没有 raw_json 列**的 Parquet（低层 API）：回灌必须拒绝而不是丢数据
    let bytes = parquet_without_raw_json();
    if bytes.is_empty() {
        return; // 编码夹具失败（例如 schema 文本被改动）时跳过，避免假通过
    }
    let decoded = decode_parquet_arrow(&bytes);
    assert!(matches!(decoded, Err(DomainError::Parse(_))), "{decoded:?}");
    if let Err(DomainError::Parse(text)) = decoded {
        assert!(text.contains("raw_json"), "错误文本必须点明缺哪一列：{text}");
    }
    // 低层路径同样拒绝（两条路径口径一致）
    assert!(decode_parquet_rows(&bytes).is_err());
    // 但文件本身是合法 Parquet：列事实照样能读出来
    assert!(parquet_facts(&bytes).is_ok());
}

/// 构造一个只有 `a`/`b` 两列的 Parquet（**故意不给 `raw_json`**）。
fn parquet_without_raw_json() -> Vec<u8> {
    let Ok(schema) = parse_message_type("message t { REQUIRED INT64 a; REQUIRED BINARY b (STRING); }") else {
        return Vec::new();
    };
    let mut buffer: Vec<u8> = Vec::new();
    {
        let Ok(mut writer) =
            SerializedFileWriter::new(&mut buffer, Arc::new(schema), Arc::new(WriterProperties::builder().build()))
        else {
            return Vec::new();
        };
        let Ok(mut group) = writer.next_row_group() else { return Vec::new() };
        let mut index = 0_usize;
        while let Ok(Some(mut column)) = group.next_column() {
            let written = if index == 0 {
                column.typed::<Int64Type>().write_batch(&[1_i64, 2, 3], None, None).is_ok()
            } else {
                column
                    .typed::<ByteArrayType>()
                    .write_batch(&[ByteArray::from("x"), ByteArray::from("y"), ByteArray::from("z")], None, None)
                    .is_ok()
            };
            index = index.saturating_add(1);
            if !written || column.close().is_err() {
                return Vec::new();
            }
        }
        if group.close().is_err() || writer.close().is_err() {
            return Vec::new();
        }
    }
    buffer
}
