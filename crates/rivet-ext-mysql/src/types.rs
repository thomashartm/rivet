//! The first type mapping: MySQL column types to Arrow types (ticket #15).
//!
//! The driver uses the text protocol, so each value arrives as text or as
//! raw bytes. A type outside the mapping keeps its text form in `Utf8`; its
//! MySQL type name is in [`ColumnMetadata::source_type`].

use std::sync::Arc;

use arrow_array::{
    ArrayRef, BinaryArray, Float32Array, Float64Array, Int8Array, Int16Array, Int32Array,
    Int64Array, StringArray, UInt8Array, UInt16Array, UInt32Array, UInt64Array,
};
use arrow_schema::{DataType, Field};
use mysql_async::consts::{ColumnFlags, ColumnType};
use mysql_async::prelude::FromValue;
use mysql_async::{Column, Value, from_value_opt};
use rivet_sdk::error::{Error, Result};
use rivet_sdk::model::ColumnMetadata;

/// The character set number that marks binary data.
const BINARY_CHARSET: u16 = 63;

/// The Arrow type of one result column.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Kind {
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float32,
    Float64,
    Utf8,
    Binary,
}

impl Kind {
    /// The Arrow type of the column.
    pub(crate) fn of(column: &Column) -> Self {
        use ColumnType::*;
        let unsigned = column.flags().contains(ColumnFlags::UNSIGNED_FLAG);
        let binary = column.character_set() == BINARY_CHARSET;
        match column.column_type() {
            // `boolean` is `tinyint(1)` and can hold any tinyint, for example
            // 2: it is a number, so no value is lost (maintainer decision).
            MYSQL_TYPE_TINY if unsigned => Self::UInt8,
            MYSQL_TYPE_TINY => Self::Int8,
            MYSQL_TYPE_SHORT if unsigned => Self::UInt16,
            MYSQL_TYPE_SHORT => Self::Int16,
            MYSQL_TYPE_INT24 | MYSQL_TYPE_LONG if unsigned => Self::UInt32,
            MYSQL_TYPE_INT24 | MYSQL_TYPE_LONG => Self::Int32,
            MYSQL_TYPE_LONGLONG if unsigned => Self::UInt64,
            MYSQL_TYPE_LONGLONG => Self::Int64,
            MYSQL_TYPE_FLOAT => Self::Float32,
            MYSQL_TYPE_DOUBLE => Self::Float64,
            MYSQL_TYPE_VARCHAR
            | MYSQL_TYPE_VAR_STRING
            | MYSQL_TYPE_STRING
            | MYSQL_TYPE_TINY_BLOB
            | MYSQL_TYPE_MEDIUM_BLOB
            | MYSQL_TYPE_LONG_BLOB
            | MYSQL_TYPE_BLOB
                if binary =>
            {
                Self::Binary
            }
            // Their text form is raw bytes, not UTF-8.
            MYSQL_TYPE_BIT | MYSQL_TYPE_GEOMETRY => Self::Binary,
            _ => Self::Utf8,
        }
    }

    fn data_type(self) -> DataType {
        match self {
            Self::Int8 => DataType::Int8,
            Self::Int16 => DataType::Int16,
            Self::Int32 => DataType::Int32,
            Self::Int64 => DataType::Int64,
            Self::UInt8 => DataType::UInt8,
            Self::UInt16 => DataType::UInt16,
            Self::UInt32 => DataType::UInt32,
            Self::UInt64 => DataType::UInt64,
            Self::Float32 => DataType::Float32,
            Self::Float64 => DataType::Float64,
            Self::Utf8 => DataType::Utf8,
            Self::Binary => DataType::Binary,
        }
    }

    /// Makes the Arrow array of one column from its values. `name` is only
    /// for the error message.
    pub(crate) fn array(self, name: &str, values: Vec<Value>) -> Result<ArrayRef> {
        Ok(match self {
            Self::Int8 => Arc::new(Int8Array::from(convert::<i8>(name, values)?)),
            Self::Int16 => Arc::new(Int16Array::from(convert::<i16>(name, values)?)),
            Self::Int32 => Arc::new(Int32Array::from(convert::<i32>(name, values)?)),
            Self::Int64 => Arc::new(Int64Array::from(convert::<i64>(name, values)?)),
            Self::UInt8 => Arc::new(UInt8Array::from(convert::<u8>(name, values)?)),
            Self::UInt16 => Arc::new(UInt16Array::from(convert::<u16>(name, values)?)),
            Self::UInt32 => Arc::new(UInt32Array::from(convert::<u32>(name, values)?)),
            Self::UInt64 => Arc::new(UInt64Array::from(convert::<u64>(name, values)?)),
            Self::Float32 => Arc::new(Float32Array::from(convert::<f32>(name, values)?)),
            Self::Float64 => Arc::new(Float64Array::from(convert::<f64>(name, values)?)),
            Self::Utf8 => Arc::new(StringArray::from(convert::<String>(name, values)?)),
            Self::Binary => Arc::new(
                convert::<Vec<u8>>(name, values)?
                    .into_iter()
                    .collect::<BinaryArray>(),
            ),
        })
    }
}

/// Converts the values of one column. NULL becomes `None`.
fn convert<T: FromValue>(name: &str, values: Vec<Value>) -> Result<Vec<Option<T>>> {
    values
        .into_iter()
        .map(|value| {
            // The value is not in the message: it is user data.
            from_value_opt::<Option<T>>(value).map_err(|_| {
                Error::internal(format!(
                    "MySQL sent a value of column `{name}` that is not a valid {}",
                    std::any::type_name::<T>()
                ))
            })
        })
        .collect()
}

/// The Arrow field, the column metadata and the kind of one result column.
pub(crate) fn describe(column: &Column) -> (Field, ColumnMetadata, Kind) {
    let kind = Kind::of(column);
    let nullable = !column.flags().contains(ColumnFlags::NOT_NULL_FLAG);
    let field = Field::new(column.name_str(), kind.data_type(), nullable);
    (
        field,
        ColumnMetadata::new(type_name(column), nullable),
        kind,
    )
}

/// The MySQL type name of a column, for example `int unsigned` or `decimal`.
fn type_name(column: &Column) -> String {
    use ColumnType::*;
    let binary = column.character_set() == BINARY_CHARSET;
    let name = match column.column_type() {
        MYSQL_TYPE_TINY if column.column_length() == 1 => "tinyint(1)",
        MYSQL_TYPE_TINY => "tinyint",
        MYSQL_TYPE_SHORT => "smallint",
        MYSQL_TYPE_INT24 => "mediumint",
        MYSQL_TYPE_LONG => "int",
        MYSQL_TYPE_LONGLONG => "bigint",
        MYSQL_TYPE_FLOAT => "float",
        MYSQL_TYPE_DOUBLE => "double",
        MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL => "decimal",
        MYSQL_TYPE_NULL => "null",
        MYSQL_TYPE_TIMESTAMP | MYSQL_TYPE_TIMESTAMP2 => "timestamp",
        MYSQL_TYPE_DATE | MYSQL_TYPE_NEWDATE => "date",
        MYSQL_TYPE_TIME | MYSQL_TYPE_TIME2 => "time",
        MYSQL_TYPE_DATETIME | MYSQL_TYPE_DATETIME2 => "datetime",
        MYSQL_TYPE_YEAR => "year",
        MYSQL_TYPE_VARCHAR | MYSQL_TYPE_VAR_STRING if binary => "varbinary",
        MYSQL_TYPE_VARCHAR | MYSQL_TYPE_VAR_STRING => "varchar",
        MYSQL_TYPE_STRING if binary => "binary",
        MYSQL_TYPE_STRING => "char",
        MYSQL_TYPE_TINY_BLOB | MYSQL_TYPE_MEDIUM_BLOB | MYSQL_TYPE_LONG_BLOB | MYSQL_TYPE_BLOB
            if binary =>
        {
            "blob"
        }
        MYSQL_TYPE_TINY_BLOB | MYSQL_TYPE_MEDIUM_BLOB | MYSQL_TYPE_LONG_BLOB | MYSQL_TYPE_BLOB => {
            "text"
        }
        MYSQL_TYPE_BIT => "bit",
        MYSQL_TYPE_ENUM => "enum",
        MYSQL_TYPE_SET => "set",
        MYSQL_TYPE_GEOMETRY => "geometry",
        MYSQL_TYPE_JSON => "json",
        MYSQL_TYPE_VECTOR => "vector",
        MYSQL_TYPE_TYPED_ARRAY | MYSQL_TYPE_UNKNOWN => "unknown",
    };
    // `year` has the flag too, but is not a number type.
    let numeric = column.column_type().is_numeric_type() && column.column_type() != MYSQL_TYPE_YEAR;
    if numeric && column.flags().contains(ColumnFlags::UNSIGNED_FLAG) {
        format!("{name} unsigned")
    } else {
        name.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::Array;

    const UTF8MB4: u16 = 255;

    fn column(column_type: ColumnType) -> Column {
        Column::new(column_type)
            .with_name(b"c")
            .with_character_set(BINARY_CHARSET)
    }

    fn unsigned(column_type: ColumnType) -> Column {
        column(column_type).with_flags(ColumnFlags::UNSIGNED_FLAG)
    }

    fn text(column_type: ColumnType) -> Column {
        column(column_type).with_character_set(UTF8MB4)
    }

    fn bytes(text: &str) -> Value {
        Value::Bytes(text.as_bytes().to_vec())
    }

    /// Each type of the first mapping, with the text the server sends and
    /// NULL.
    #[test]
    fn maps_each_type_of_the_first_mapping_with_null() {
        use ColumnType::*;
        let cases: Vec<(Column, DataType, &str, &str)> = vec![
            (
                column(MYSQL_TYPE_TINY).with_column_length(1),
                DataType::Int8,
                "2",
                "tinyint(1)",
            ),
            (
                column(MYSQL_TYPE_TINY).with_column_length(4),
                DataType::Int8,
                "-8",
                "tinyint",
            ),
            (
                unsigned(MYSQL_TYPE_TINY).with_column_length(3),
                DataType::UInt8,
                "255",
                "tinyint unsigned",
            ),
            (column(MYSQL_TYPE_SHORT), DataType::Int16, "-7", "smallint"),
            (
                unsigned(MYSQL_TYPE_SHORT),
                DataType::UInt16,
                "65535",
                "smallint unsigned",
            ),
            (
                column(MYSQL_TYPE_INT24),
                DataType::Int32,
                "-70000",
                "mediumint",
            ),
            (column(MYSQL_TYPE_LONG), DataType::Int32, "70000", "int"),
            (
                unsigned(MYSQL_TYPE_LONG),
                DataType::UInt32,
                "4294967295",
                "int unsigned",
            ),
            (
                column(MYSQL_TYPE_LONGLONG),
                DataType::Int64,
                "9223372036854775807",
                "bigint",
            ),
            (
                unsigned(MYSQL_TYPE_LONGLONG),
                DataType::UInt64,
                "18446744073709551615",
                "bigint unsigned",
            ),
            (column(MYSQL_TYPE_FLOAT), DataType::Float32, "1.5", "float"),
            (
                column(MYSQL_TYPE_DOUBLE),
                DataType::Float64,
                "2.25",
                "double",
            ),
            (
                text(MYSQL_TYPE_VAR_STRING),
                DataType::Utf8,
                "héllo",
                "varchar",
            ),
            (text(MYSQL_TYPE_STRING), DataType::Utf8, "x", "char"),
            (text(MYSQL_TYPE_BLOB), DataType::Utf8, "long text", "text"),
            (
                column(MYSQL_TYPE_VAR_STRING),
                DataType::Binary,
                "\u{1}\u{2}",
                "varbinary",
            ),
            (column(MYSQL_TYPE_BLOB), DataType::Binary, "blob", "blob"),
            // Every other type: text form, with the type name.
            (
                column(MYSQL_TYPE_NEWDECIMAL),
                DataType::Utf8,
                "12.50",
                "decimal",
            ),
            (
                unsigned(MYSQL_TYPE_NEWDECIMAL),
                DataType::Utf8,
                "1.0",
                "decimal unsigned",
            ),
            (
                column(MYSQL_TYPE_DATE),
                DataType::Utf8,
                "2026-11-26",
                "date",
            ),
            (
                column(MYSQL_TYPE_DATETIME),
                DataType::Utf8,
                "2026-11-26 10:00:00",
                "datetime",
            ),
            (column(MYSQL_TYPE_TIME), DataType::Utf8, "-10:00:00", "time"),
            (
                column(MYSQL_TYPE_JSON),
                DataType::Utf8,
                "{\"a\": 1}",
                "json",
            ),
            (unsigned(MYSQL_TYPE_YEAR), DataType::Utf8, "2026", "year"),
            (column(MYSQL_TYPE_BIT), DataType::Binary, "\u{5}", "bit"),
        ];
        for (column, data_type, value, source_type) in cases {
            let (field, metadata, kind) = describe(&column);
            assert_eq!(field.data_type(), &data_type, "{source_type}");
            assert_eq!(metadata.source_type, source_type);
            assert!(metadata.nullable && field.is_nullable(), "{source_type}");
            let array = kind.array("c", vec![bytes(value), Value::NULL]).unwrap();
            assert_eq!(array.data_type(), &data_type, "{source_type}");
            assert_eq!((array.len(), array.null_count()), (2, 1), "{source_type}");
            assert!(array.is_valid(0), "{source_type}");
        }
    }

    #[test]
    fn converts_the_text_form_of_each_value() {
        let int = Kind::Int64
            .array("c", vec![bytes("-9223372036854775808")])
            .unwrap();
        assert_eq!(
            int.as_ref(),
            &Int64Array::from(vec![i64::MIN]) as &dyn Array
        );
        let max = Kind::UInt64
            .array("c", vec![bytes("18446744073709551615")])
            .unwrap();
        assert_eq!(
            max.as_ref(),
            &UInt64Array::from(vec![u64::MAX]) as &dyn Array
        );
        // A `tinyint(1)` (`boolean`) can hold more than 0 and 1.
        let flags = Kind::Int8
            .array("c", vec![bytes("0"), bytes("1"), bytes("2"), bytes("-1")])
            .unwrap();
        assert_eq!(
            flags.as_ref(),
            &Int8Array::from(vec![0, 1, 2, -1]) as &dyn Array
        );
        let float = Kind::Float32.array("c", vec![bytes("1.5")]).unwrap();
        assert_eq!(float.as_ref(), &Float32Array::from(vec![1.5]) as &dyn Array);
        let binary = Kind::Binary
            .array("c", vec![Value::Bytes(vec![0, 255])])
            .unwrap();
        let expected = BinaryArray::from_vec(vec![&[0, 255]]);
        assert_eq!(binary.as_ref(), &expected as &dyn Array);
    }

    #[test]
    fn not_null_column_is_not_nullable() {
        let column = column(ColumnType::MYSQL_TYPE_LONG).with_flags(ColumnFlags::NOT_NULL_FLAG);
        let (field, metadata, _) = describe(&column);
        assert!(!field.is_nullable() && !metadata.nullable);
    }

    #[test]
    fn value_that_does_not_fit_is_an_internal_error_without_the_value() {
        let error = Kind::Int8.array("age", vec![bytes("300")]).unwrap_err();
        assert_eq!(error.category(), rivet_sdk::error::ErrorCategory::Internal);
        assert!(error.message().contains("`age`"), "{error:?}");
        assert!(!format!("{error:?}").contains("300"), "{error:?}");
        let error = Kind::Utf8.array("t", vec![Value::Bytes(vec![0xff])]);
        assert!(error.is_err());
    }
}
