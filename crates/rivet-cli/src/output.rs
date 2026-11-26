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

/// The text of one whole result with the column names `header`.
pub fn render(format: Format, header: &[String], batches: &[RecordBatch]) -> String {
    match format {
        Format::Table => {
            let rows: Vec<Vec<String>> = batches
                .iter()
                .flat_map(|batch| texts(batch, "NULL"))
                .collect();
            table(header, &rows)
        }
        Format::Csv | Format::Json => batches.iter().fold(start(format, header), |out, batch| {
            out + &rows(format, header, batch)
        }),
    }
}

/// The text before the first row: the CSV header line. Empty for JSON.
/// The table is not streamed: it needs all rows to align them.
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

/// Aligns `header` and `rows` into columns, with a row count at the end.
fn table(header: &[String], rows: &[Vec<String>]) -> String {
    let widths: Vec<usize> = (0..header.len())
        .map(|i| {
            rows.iter()
                .map(|row| row[i].chars().count())
                .chain([header[i].chars().count()])
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
    if !header.is_empty() {
        text += &line(header);
        let rule: Vec<String> = widths.iter().map(|width| "-".repeat(*width)).collect();
        text += &rule.join("-+-");
        text += "\n";
        for row in rows {
            text += &line(row);
        }
    }
    text + &format!("({} rows)\n", rows.len())
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
}
