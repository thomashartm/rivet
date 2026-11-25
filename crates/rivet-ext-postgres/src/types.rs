//! The first type mapping: PostgreSQL types to Arrow types.
//!
//! The driver reads values in the text format of PostgreSQL. A typed column
//! parses the text. Each type that the mapping does not know is its text
//! form in a `Utf8` column.

use std::str::FromStr;
use std::sync::Arc;

use arrow_array::ArrayRef;
use arrow_array::builder::{
    BinaryBuilder, BooleanBuilder, Float32Builder, Float64Builder, Int16Builder, Int32Builder,
    Int64Builder, StringBuilder,
};
use arrow_schema::DataType;
use rivet_sdk::error::{Error, Result};
use tokio_postgres::types::Type;

/// Returns the Arrow type of a PostgreSQL type.
pub(crate) fn data_type(source: &Type) -> DataType {
    match *source {
        Type::BOOL => DataType::Boolean,
        Type::INT2 => DataType::Int16,
        Type::INT4 => DataType::Int32,
        Type::INT8 => DataType::Int64,
        Type::FLOAT4 => DataType::Float32,
        Type::FLOAT8 => DataType::Float64,
        Type::BYTEA => DataType::Binary,
        _ => DataType::Utf8,
    }
}

/// Collects the values of one column for one batch.
pub(crate) enum ColumnBuilder {
    Boolean(BooleanBuilder),
    Int16(Int16Builder),
    Int32(Int32Builder),
    Int64(Int64Builder),
    Float32(Float32Builder),
    Float64(Float64Builder),
    Binary(BinaryBuilder),
    Utf8(StringBuilder),
}

fn parse<T: FromStr>(text: &str, type_name: &str) -> Result<T> {
    text.parse()
        .map_err(|_| unreadable(type_name, "is not a valid value"))
}

fn unreadable(type_name: &str, reason: &str) -> Error {
    // The value is not in the message: it can be confidential data.
    Error::internal(format!(
        "PostgreSQL sent a `{type_name}` value that {reason}"
    ))
}

/// Decodes the hex format of `bytea` (`\x0102`), the default of
/// PostgreSQL since version 9.0.
fn decode_bytea(text: &str) -> Result<Vec<u8>> {
    let not_hex = || {
        unreadable(
            "bytea",
            "is not in the hex format (set bytea_output to hex)",
        )
    };
    let digits = text.strip_prefix("\\x").ok_or_else(not_hex)?;
    if digits.len() % 2 != 0 {
        return Err(not_hex());
    }
    (0..digits.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&digits[index..index + 2], 16).map_err(|_| not_hex()))
        .collect()
}

impl ColumnBuilder {
    /// Creates the builder for a column of the PostgreSQL type `source`.
    pub(crate) fn new(source: &Type) -> Self {
        match data_type(source) {
            DataType::Boolean => Self::Boolean(BooleanBuilder::new()),
            DataType::Int16 => Self::Int16(Int16Builder::new()),
            DataType::Int32 => Self::Int32(Int32Builder::new()),
            DataType::Int64 => Self::Int64(Int64Builder::new()),
            DataType::Float32 => Self::Float32(Float32Builder::new()),
            DataType::Float64 => Self::Float64(Float64Builder::new()),
            DataType::Binary => Self::Binary(BinaryBuilder::new()),
            _ => Self::Utf8(StringBuilder::new()),
        }
    }

    /// Appends one value in the text format of PostgreSQL. `None` is NULL.
    ///
    /// Fails with an `internal` error if the text is not a value of the type.
    pub(crate) fn append(&mut self, value: Option<&str>, type_name: &str) -> Result<()> {
        let Some(text) = value else {
            match self {
                Self::Boolean(builder) => builder.append_null(),
                Self::Int16(builder) => builder.append_null(),
                Self::Int32(builder) => builder.append_null(),
                Self::Int64(builder) => builder.append_null(),
                Self::Float32(builder) => builder.append_null(),
                Self::Float64(builder) => builder.append_null(),
                Self::Binary(builder) => builder.append_null(),
                Self::Utf8(builder) => builder.append_null(),
            }
            return Ok(());
        };
        match self {
            Self::Boolean(builder) => builder.append_value(match text {
                "t" => true,
                "f" => false,
                _ => return Err(unreadable(type_name, "is not `t` or `f`")),
            }),
            Self::Int16(builder) => builder.append_value(parse(text, type_name)?),
            Self::Int32(builder) => builder.append_value(parse(text, type_name)?),
            Self::Int64(builder) => builder.append_value(parse(text, type_name)?),
            // Rust reads `Infinity`, `-Infinity` and `NaN` as PostgreSQL writes them.
            Self::Float32(builder) => builder.append_value(parse::<f32>(text, type_name)?),
            Self::Float64(builder) => builder.append_value(parse::<f64>(text, type_name)?),
            Self::Binary(builder) => builder.append_value(decode_bytea(text)?),
            Self::Utf8(builder) => builder.append_value(text),
        }
        Ok(())
    }

    /// Returns the values collected so far and empties the builder.
    pub(crate) fn finish(&mut self) -> ArrayRef {
        match self {
            Self::Boolean(builder) => Arc::new(builder.finish()),
            Self::Int16(builder) => Arc::new(builder.finish()),
            Self::Int32(builder) => Arc::new(builder.finish()),
            Self::Int64(builder) => Arc::new(builder.finish()),
            Self::Float32(builder) => Arc::new(builder.finish()),
            Self::Float64(builder) => Arc::new(builder.finish()),
            Self::Binary(builder) => Arc::new(builder.finish()),
            Self::Utf8(builder) => Arc::new(builder.finish()),
        }
    }
}

#[cfg(test)]
mod tests {
    use arrow_array::{
        Array, BinaryArray, BooleanArray, Float32Array, Float64Array, Int16Array, Int32Array,
        Int64Array, StringArray,
    };
    use rivet_sdk::error::ErrorCategory;

    use super::*;

    /// Builds one column of `source` from `values`.
    fn column(source: &Type, values: &[Option<&str>]) -> Result<ArrayRef> {
        let mut builder = ColumnBuilder::new(source);
        for value in values {
            builder.append(*value, source.name())?;
        }
        Ok(builder.finish())
    }

    #[test]
    fn known_types_get_their_arrow_type_and_others_are_text() {
        let cases = [
            (Type::BOOL, DataType::Boolean),
            (Type::INT2, DataType::Int16),
            (Type::INT4, DataType::Int32),
            (Type::INT8, DataType::Int64),
            (Type::FLOAT4, DataType::Float32),
            (Type::FLOAT8, DataType::Float64),
            (Type::TEXT, DataType::Utf8),
            (Type::VARCHAR, DataType::Utf8),
            (Type::BPCHAR, DataType::Utf8),
            (Type::NAME, DataType::Utf8),
            (Type::BYTEA, DataType::Binary),
            (Type::NUMERIC, DataType::Utf8),
            (Type::TIMESTAMPTZ, DataType::Utf8),
            (Type::UUID, DataType::Utf8),
            (Type::JSONB, DataType::Utf8),
        ];
        for (source, expected) in cases {
            assert_eq!(data_type(&source), expected, "{source}");
            let array = column(&source, &[None]).unwrap();
            assert_eq!(array.data_type(), &expected, "{source}");
            assert!(array.is_null(0), "{source}: NULL");
        }
    }

    #[test]
    fn text_values_are_parsed_with_null() {
        let bools = column(&Type::BOOL, &[Some("t"), Some("f"), None]).unwrap();
        let expected = BooleanArray::from(vec![Some(true), Some(false), None]);
        assert_eq!(bools.as_ref(), &expected as &dyn Array);

        let ints = column(&Type::INT2, &[Some("-32768"), None]).unwrap();
        assert_eq!(
            ints.as_ref(),
            &Int16Array::from(vec![Some(i16::MIN), None]) as &dyn Array
        );
        let ints = column(&Type::INT4, &[Some("70000"), None]).unwrap();
        assert_eq!(
            ints.as_ref(),
            &Int32Array::from(vec![Some(70_000), None]) as &dyn Array
        );
        let ints = column(&Type::INT8, &[Some("9223372036854775807"), None]).unwrap();
        assert_eq!(
            ints.as_ref(),
            &Int64Array::from(vec![Some(i64::MAX), None]) as &dyn Array
        );

        let floats = column(&Type::FLOAT4, &[Some("1.5"), Some("-Infinity"), None]).unwrap();
        let expected = Float32Array::from(vec![Some(1.5), Some(f32::NEG_INFINITY), None]);
        assert_eq!(floats.as_ref(), &expected as &dyn Array);
        let floats = column(&Type::FLOAT8, &[Some("NaN"), Some("Infinity")]).unwrap();
        let floats = floats.as_any().downcast_ref::<Float64Array>().unwrap();
        assert!(floats.value(0).is_nan());
        assert_eq!(floats.value(1), f64::INFINITY);

        let bytes = column(&Type::BYTEA, &[Some("\\x01ff"), Some("\\x"), None]).unwrap();
        let expected = BinaryArray::from_opt_vec(vec![Some(&[1, 255]), Some(&[]), None]);
        assert_eq!(bytes.as_ref(), &expected as &dyn Array);

        let text = column(&Type::NUMERIC, &[Some("12.50"), None]).unwrap();
        let expected = StringArray::from(vec![Some("12.50"), None]);
        assert_eq!(text.as_ref(), &expected as &dyn Array);
    }

    #[test]
    fn wrong_text_is_an_internal_error_without_the_value() {
        for (source, text) in [
            (Type::BOOL, "yes"),
            (Type::INT2, "70000"),
            (Type::INT8, "1.5"),
            (Type::FLOAT8, "abc"),
            (Type::BYTEA, "\\x0"),
            (Type::BYTEA, "\\001"),
        ] {
            let error = column(&source, &[Some(text)]).unwrap_err();
            assert_eq!(error.category(), ErrorCategory::Internal, "{source}");
            assert!(error.message().contains(source.name()), "{error}");
            assert!(!error.message().contains(text), "{error}");
        }
    }
}
