use crate::{CwtAny, EsdicawtSpecError, TO_BE_REDACTED_TAG};
use ciborium::Value;

pub trait Select: std::fmt::Debug + CwtAny + Clone {
    type Error;

    fn select(self) -> Result<Value, <Self as Select>::Error>
    where
        <Self as Select>::Error: From<ciborium::value::Error>,
    {
        let mut value = Value::serialized(&self)?;
        let value = select_all(&mut value);
        Ok(value)
    }
}

pub fn select_all(value: &mut Value) -> Value {
    let value = match value {
        Value::Map(map) => {
            for (l, v) in map {
                match v {
                    Value::Map(_) | Value::Array(_) => *v = select_all(v),
                    _ => {}
                };
                *l = sd(l.clone())
            }
            value
        }
        Value::Array(array) => {
            for item in array {
                select_all(item);
            }
            value
        }
        v => {
            *v = sd(v.clone());
            v
        }
    };
    value.clone()
}

pub fn select_root(value: &mut Value) -> Value {
    let value = match value {
        Value::Map(map) => {
            for (l, _) in map {
                *l = sd(l.clone())
            }
            value
        }
        value => value,
    };
    value.clone()
}

pub fn select_none(value: &mut Value) -> Value {
    value.clone()
}

impl Select for Value {
    type Error = EsdicawtSpecError;
}

pub fn sd(v: Value) -> Value {
    Value::Tag(TO_BE_REDACTED_TAG, Box::new(v))
}
