//! Turns a result into text: an aligned table, CSV or JSON lines.

use std::str::FromStr;

use arrow_array::cast::AsArray;
use arrow_array::types::{Float32Type, Float64Type, Int8Type, Int16Type, Int32Type, Int64Type};
use arrow_array::{Array, RecordBatch};
use arrow_schema::DataType;
use rivet_sdk::error::Error;
use serde_json::Value;

/// The output format of a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Aligned columns and a row count, for people.
    Table,
    /// RFC 4180 CSV with a header line. NULL is an empty field.
    Csv,
    /// One JSON object per row (JSON lines), with typed values.
    Json,
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Error> {
        match name {
            "table" => Ok(Self::Table),
            "csv" => Ok(Self::Csv),
            "json" => Ok(Self::Json),
            _ => Err(Error::user(format!(
                "unknown format `{name}`: use table, csv or json"
            ))),
        }
    }
}

/// The text of one whole result with the column names `header`. For tests;
/// the prompt streams with `start`, `rows` and `TablePages`.
#[cfg(test)]
pub fn render(format: Format, header: &[String], batches: &[RecordBatch]) -> String {
    match format {
        Format::Table => {
            let mut out = String::new();
            let mut write = |text: String| -> Result<(), Error> {
                out += &text;
                Ok(())
            };
            let mut pages = TablePages::new(header);
            for batch in batches {
                pages.push(batch, &mut write).expect("writing to a String");
            }
            pages.finish(&mut write).expect("writing to a String");
            out
        }
        Format::Csv | Format::Json => batches.iter().fold(start(format, header), |out, batch| {
            out + &rows(format, header, batch)
        }),
    }
}

/// The text before the first row: the CSV header line. Empty for JSON and
/// the table (see [`TablePages`]).
pub fn start(format: Format, header: &[String]) -> String {
    match format {
        Format::Csv => csv_line(header),
        Format::Table | Format::Json => String::new(),
    }
}

/// The CSV or JSON text of the rows of one batch. Empty for the table.
pub fn rows(format: Format, header: &[String], batch: &RecordBatch) -> String {
    match format {
        Format::Table => String::new(),
        Format::Csv => texts(batch, "").iter().map(|row| csv_line(row)).collect(),
        Format::Json => (0..batch.num_rows())
            .map(|row| {
                let pairs: Vec<String> = header
                    .iter()
                    .zip(batch.columns())
                    .map(|(name, column)| {
                        format!(
                            "{}:{}",
                            Value::from(name.as_str()),
                            json(column.as_ref(), row)
                        )
                    })
                    .collect();
                format!("{{{}}}\n", pairs.join(","))
            })
            .collect(),
    }
}

/// The rows of `batch` as text, with `null` for NULL.
fn texts(batch: &RecordBatch, null: &str) -> Vec<Vec<String>> {
    (0..batch.num_rows())
        .map(|row| {
            batch
                .columns()
                .iter()
                .map(|column| text(column.as_ref(), row).unwrap_or_else(|| null.to_owned()))
                .collect()
        })
        .collect()
}

fn csv_line(cells: &[String]) -> String {
    cells
        .iter()
        .map(|cell| csv_field(cell))
        .collect::<Vec<_>>()
        .join(",")
        + "\n"
}

/// One value as text, `None` for NULL. Covers the type set of the drivers
/// (ADR-0025); other types show their type name.
fn text(column: &dyn Array, row: usize) -> Option<String> {
    if column.is_null(row) {
        return None;
    }
    Some(match column.data_type() {
        DataType::Boolean => column.as_boolean().value(row).to_string(),
        DataType::Int8 => column.as_primitive::<Int8Type>().value(row).to_string(),
        DataType::Int16 => column.as_primitive::<Int16Type>().value(row).to_string(),
        DataType::Int32 => column.as_primitive::<Int32Type>().value(row).to_string(),
        DataType::Int64 => column.as_primitive::<Int64Type>().value(row).to_string(),
        DataType::Float32 => column.as_primitive::<Float32Type>().value(row).to_string(),
        DataType::Float64 => column.as_primitive::<Float64Type>().value(row).to_string(),
        DataType::Utf8 => column.as_string::<i32>().value(row).to_owned(),
        DataType::Binary => column
            .as_binary::<i32>()
            .value(row)
            .iter()
            .fold("\\x".to_owned(), |hex, byte| hex + &format!("{byte:02x}")),
        other => format!("<{other}>"),
    })
}

/// One value as JSON: numbers and booleans keep their type. A float that
/// JSON cannot hold (NaN, infinity) becomes a string.
fn json(column: &dyn Array, row: usize) -> Value {
    if column.is_null(row) {
        return Value::Null;
    }
    match column.data_type() {
        DataType::Boolean => column.as_boolean().value(row).into(),
        DataType::Int8 => column.as_primitive::<Int8Type>().value(row).into(),
        DataType::Int16 => column.as_primitive::<Int16Type>().value(row).into(),
        DataType::Int32 => column.as_primitive::<Int32Type>().value(row).into(),
        DataType::Int64 => column.as_primitive::<Int64Type>().value(row).into(),
        DataType::Float32 | DataType::Float64 => {
            let value = if column.data_type() == &DataType::Float32 {
                f64::from(column.as_primitive::<Float32Type>().value(row))
            } else {
                column.as_primitive::<Float64Type>().value(row)
            };
            serde_json::Number::from_f64(value)
                .map_or_else(|| value.to_string().into(), Value::Number)
        }
        _ => text(column, row).map_or(Value::Null, Value::from),
    }
}

/// Quotes a CSV field if it holds a separator, a quote or a line break.
fn csv_field(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

/// The most rows of one table block.
const PAGE_ROWS: usize = 1000;

/// A table printed in blocks of [`PAGE_ROWS`] rows, so memory is bounded by
/// one block. The header comes once at the top; each block aligns by its own
/// widths, like psql with `FETCH_COUNT`.
// shortcut: columns can be misaligned between blocks, since a block does not
// know the widths of later rows; align globally if that hurts readers.
pub struct TablePages<'a> {
    header: &'a [String],
    rows: Vec<Vec<String>>,
    total: usize,
    started: bool,
}

impl<'a> TablePages<'a> {
    pub fn new(header: &'a [String]) -> Self {
        Self {
            header,
            rows: Vec::new(),
            total: 0,
            started: false,
        }
    }

    /// Buffers the rows of `batch` and passes each full block to `write`.
    pub fn push(
        &mut self,
        batch: &RecordBatch,
        write: &mut impl FnMut(String) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for row in texts(batch, "NULL") {
            self.rows.push(row);
            if self.rows.len() == PAGE_ROWS {
                self.flush(write)?;
            }
        }
        Ok(())
    }

    /// Passes the last block and the total row count to `write`.
    pub fn finish(
        mut self,
        write: &mut impl FnMut(String) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.flush(write)?;
        write(format!("({} rows)\n", self.total))
    }

    fn flush(&mut self, write: &mut impl FnMut(String) -> Result<(), Error>) -> Result<(), Error> {
        if self.started && self.rows.is_empty() {
            return Ok(());
        }
        let text = block(self.header, &self.rows, !self.started);
        self.started = true;
        self.total += self.rows.len();
        self.rows.clear();
        if text.is_empty() { Ok(()) } else { write(text) }
    }
}

/// Aligns `rows` into columns; `with_header` adds the header and rule line.
fn block(header: &[String], rows: &[Vec<String>], with_header: bool) -> String {
    if header.is_empty() {
        return String::new();
    }
    let widths: Vec<usize> = (0..header.len())
        .map(|i| {
            rows.iter()
                .map(|row| row[i].chars().count())
                .chain(with_header.then(|| header[i].chars().count()))
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |cells: &[String]| {
        let padded: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        padded.join(" | ").trim_end().to_owned() + "\n"
    };
    let mut text = String::new();
    if with_header {
        text += &line(header);
        let rule: Vec<String> = widths.iter().map(|width| "-".repeat(*width)).collect();
        text += &rule.join("-+-");
        text += "\n";
    }
    for row in rows {
        text += &line(row);
    }
    text
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow_array::{ArrayRef, BooleanArray, Float64Array, Int32Array, StringArray};

    use super::*;

    fn sample() -> (Vec<String>, Vec<RecordBatch>) {
        let columns: Vec<(&str, ArrayRef)> = vec![
            ("id", Arc::new(Int32Array::from(vec![Some(1), Some(22)]))),
            (
                "name",
                Arc::new(StringArray::from(vec![Some("a, \"b\""), None])),
            ),
            (
                "ok",
                Arc::new(BooleanArray::from(vec![Some(true), Some(false)])),
            ),
            ("x", Arc::new(Float64Array::from(vec![1.5, f64::NAN]))),
        ];
        let header = columns.iter().map(|(name, _)| (*name).to_owned()).collect();
        (header, vec![RecordBatch::try_from_iter(columns).unwrap()])
    }

    #[test]
    fn table_aligns_columns_and_counts_rows() {
        let (header, batches) = sample();
        assert_eq!(
            render(Format::Table, &header, &batches),
            "id | name   | ok    | x\n---+--------+-------+----\n\
             1  | a, \"b\" | true  | 1.5\n22 | NULL   | false | NaN\n(2 rows)\n"
        );
    }

    #[test]
    fn csv_quotes_and_leaves_null_empty() {
        let (header, batches) = sample();
        assert_eq!(
            render(Format::Csv, &header, &batches),
            "id,name,ok,x\n1,\"a, \"\"b\"\"\",true,1.5\n22,,false,NaN\n"
        );
    }

    #[test]
    fn json_keeps_types_and_order() {
        let (header, batches) = sample();
        assert_eq!(
            render(Format::Json, &header, &batches),
            "{\"id\":1,\"name\":\"a, \\\"b\\\"\",\"ok\":true,\"x\":1.5}\n\
             {\"id\":22,\"name\":null,\"ok\":false,\"x\":\"NaN\"}\n"
        );
    }

    #[test]
    fn format_parses_its_names() {
        assert_eq!("csv".parse::<Format>().unwrap(), Format::Csv);
        assert!("xml".parse::<Format>().is_err());
    }

    #[test]
    fn table_pages_of_1000_rows_with_one_header() {
        let header = vec!["n".to_owned()];
        let mut next = 0;
        let mut blocks = Vec::new();
        let mut write = |text: String| -> Result<(), Error> {
            blocks.push(text);
            Ok(())
        };
        let mut pages = TablePages::new(&header);
        for _ in 0..4 {
            let values: Vec<i32> = (next..next + 700).collect();
            next += 700;
            let batch =
                RecordBatch::try_from_iter([("n", Arc::new(Int32Array::from(values)) as ArrayRef)])
                    .unwrap();
            pages.push(&batch, &mut write).unwrap();
        }
        let batch = RecordBatch::try_from_iter([(
            "n",
            Arc::new(Int32Array::from(vec![9999; 200])) as ArrayRef,
        )])
        .unwrap();
        pages.push(&batch, &mut write).unwrap();
        pages.finish(&mut write).unwrap();
        // 3000 rows: three full blocks, then only the count.
        assert_eq!(blocks.len(), 4);
        assert!(blocks[0].starts_with("n\n---\n0\n"));
        assert_eq!(blocks[0].lines().count(), 1002);
        assert!(blocks[1].starts_with("1000\n"));
        assert_eq!(blocks[1].lines().count(), 1000);
        assert!(blocks[2].ends_with("9999\n"));
        assert_eq!(blocks[3], "(3000 rows)\n");
        assert_eq!(blocks.iter().filter(|b| b.contains("---\n")).count(), 1);
    }

    #[test]
    fn table_without_rows_prints_header_and_count() {
        let header = vec!["id".to_owned()];
        assert_eq!(render(Format::Table, &header, &[]), "id\n--\n(0 rows)\n");
    }
}
