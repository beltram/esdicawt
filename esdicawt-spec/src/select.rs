use crate::redacted_claims::RedactedClaimKeys;
use crate::{AnyMap, CWT_LABEL_REDACTED_KEYS, CustomClaims, EsdicawtSpecError, TO_BE_REDACTED_TAG};
use ciborium::Value;

pub trait Select: CustomClaims {
    type Error;

    fn select(self) -> Result<SelectiveDisclosure, <Self as Select>::Error>
    where
        <Self as Select>::Error: From<ciborium::value::Error>,
    {
        let mut value = Value::serialized(&self)?;
        let value = select_all(&mut value);
        Ok(value)
    }
}

pub fn select_all(value: &mut Value) -> SelectiveDisclosure {
    let value = match value {
        Value::Map(map) => {
            for (l, v) in map {
                match v {
                    Value::Map(_) | Value::Array(_) => *v = select_all(v).0,
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
    value.clone().into()
}

pub fn select_root(value: &mut Value) -> SelectiveDisclosure {
    let value = match value {
        Value::Map(map) => {
            for (l, _) in map {
                *l = sd(l.clone())
            }
            value
        }
        value => value,
    };
    value.clone().into()
}

pub fn select_none(value: &mut Value) -> SelectiveDisclosure {
    value.clone().into()
}

impl Select for AnyMap {
    type Error = EsdicawtSpecError;
}

// TODO:
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SelectiveDisclosure(pub Value);

impl SelectiveDisclosure {
    pub fn take_rcks(&mut self) -> Result<Option<RedactedClaimKeys>, EsdicawtSpecError> {
        let map = self.0.as_map_mut().ok_or(EsdicawtSpecError::ImplementationError("SD-CWT payload must be a mapping"))?;

        let mut found_rcks = None;
        for (i, (label, value)) in map.iter().enumerate() {
            if let (Value::Simple(CWT_LABEL_REDACTED_KEYS), array @ Value::Array(_)) = (label, value) {
                let rcks = Value::deserialized::<RedactedClaimKeys>(array)?;
                found_rcks = Some((i, rcks))
            }
        }

        if let Some((pos, rcks)) = found_rcks {
            map.remove(pos);
            Ok(Some(rcks))
        } else {
            Ok(None)
        }
    }
}

impl std::ops::Deref for SelectiveDisclosure {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Value> for SelectiveDisclosure {
    fn from(v: Value) -> Self {
        Self(v)
    }
}

pub fn sd(v: Value) -> Value {
    Value::Tag(TO_BE_REDACTED_TAG, Box::new(v))
}
