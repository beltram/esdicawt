use crate::CwtAny;
use ciborium::Value;

/// To be implemented on a serializable struct to select the claims the Issuer will redact.
/// Claims (or array elements) to redact must be wrapped in a tag, use `sd!` macro for that.
pub trait Select: std::fmt::Debug + PartialEq + CwtAny + Clone {
    fn select(self) -> Result<Value, ciborium::value::Error> {
        self.select_none()
    }
}

pub trait SelectExt: serde::Serialize {
    fn select_all(&mut self) -> Result<Value, ciborium::value::Error> {
        Ok(match Value::serialized(self)? {
            Value::Map(mut map) => {
                for (l, v) in &mut map {
                    match v {
                        Value::Map(_) | Value::Array(_) => *v = v.select_all()?,
                        _ => {}
                    };
                    *l = crate::sd!(l.clone())
                }
                Value::Map(map)
            }
            Value::Array(mut array) => {
                for item in &mut array {
                    *item = item.select_all()?;
                }
                Value::Array(array)
            }
            v => crate::sd!(v),
        })
    }

    fn select_root(&mut self) -> Result<Value, ciborium::value::Error> {
        Ok(match Value::serialized(self)? {
            Value::Map(mut map) => {
                for (l, _) in &mut map {
                    *l = crate::sd!(l.clone())
                }
                Value::Map(map)
            }
            value => value,
        })
    }

    fn select_none(&self) -> Result<Value, ciborium::value::Error> {
        Value::serialized(&self)
    }
}

impl<T: std::fmt::Debug + CwtAny + Clone> SelectExt for T {}

impl Select for Value {}

/// Indicates that a mapping claim or an array element must be redacted by the issuer
#[macro_export]
macro_rules! sd {
    ($l:literal) => {
        ciborium::Value::Tag(58, Box::new($l.into()))
    };
    ($v:expr) => {
        ciborium::Value::Tag(58, Box::new($v.into()))
    };
}

/// Redact in place a label or an array element
pub trait Redact {
    fn redact(&mut self);
}

impl Redact for &mut Value {
    fn redact(&mut self) {
        **self = Value::Tag(crate::TO_BE_REDACTED_TAG, Box::new(self.clone()));
    }
}
