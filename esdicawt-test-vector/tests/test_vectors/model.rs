use ciborium::Value;
use esdicawt::cwt_label;
use esdicawt_spec::{CwtAny, Select, decoy, sd};
use serde::ser::SerializeMap;

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct Payload {
    pub most_recent_inspection_passed: bool,
    #[builder(default, setter(into, strip_option))]
    pub inspector_license_number: Option<String>,
    #[builder(default)]
    pub inspection_dates: Vec<u64>,
    pub inspection_location: InspectionLocation,
}

#[derive(Debug, Copy, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr)]
#[repr(i64)]
pub enum CwtLabel {
    MostRecentInspectionPassed = 500,
    InspectorLicenseNumber = 501,
    InspectionDates = 502,
    InspectionLocation = 503,
    NestedPayload = 504,
    NestedCountry = 1,
    NestedRegion = 2,
    NestedPostalCode = 3,
    Countries = 98,
}

cwt_label!(CwtLabel);

impl serde::Serialize for Payload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(&CwtLabel::MostRecentInspectionPassed, &self.most_recent_inspection_passed)?;
        map.serialize_entry(&CwtLabel::InspectorLicenseNumber, &self.inspector_license_number)?;
        map.serialize_entry(&CwtLabel::InspectionDates, &self.inspection_dates)?;
        let location = self.inspection_location.to_cbor_value().map_err(S::Error::custom)?;
        map.serialize_entry(&CwtLabel::InspectionLocation, &location)?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for Payload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        // I'm lazy to go with a visitor
        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        let values = value.into_map().map_err(|_| D::Error::custom("expected a map"))?;

        let mut builder = PayloadBuilder::create_empty();

        for entry in values {
            match entry {
                (Value::Integer(i), Value::Bool(b)) if i == CwtLabel::MostRecentInspectionPassed => builder.most_recent_inspection_passed(b),
                (Value::Integer(i), Value::Text(s)) if i == CwtLabel::InspectorLicenseNumber => builder.inspector_license_number(s),
                (Value::Integer(i), Value::Array(values)) if i == CwtLabel::InspectionDates => {
                    let values = values.into_iter().filter(|v| !matches!(v, Value::Tag(_, _))).collect::<Vec<_>>();
                    builder.inspection_dates(Value::Array(values).deserialized().map_err(D::Error::custom)?)
                }
                (Value::Integer(i), location) if i == CwtLabel::InspectionLocation => builder.inspection_location(location.deserialized().map_err(D::Error::custom)?),
                _ => unreachable!("Unexpected claim"),
            };
        }

        builder.build().map_err(D::Error::custom)
    }
}

impl Select for Payload {
    fn select(self) -> Result<Value, ciborium::value::Error> {
        let mut map = Vec::with_capacity(4);

        map.push((CwtLabel::MostRecentInspectionPassed.into(), Value::Bool(self.most_recent_inspection_passed)));

        if let Some(inspector_license_number) = self.inspector_license_number {
            map.push((sd!(CwtLabel::InspectorLicenseNumber as i64), Value::Text(inspector_license_number)));
        }

        let inspection_dates = self
            .inspection_dates
            .iter()
            .enumerate()
            .map(|(i, &d)| if i < 2 { sd!(d) } else { Value::Integer(d.into()) })
            .collect();
        map.push((CwtLabel::InspectionDates.into(), Value::Array(inspection_dates)));

        let mut inspection_location = vec![("country".into(), Value::Text(self.inspection_location.country))];
        if let Some(region) = self.inspection_location.region {
            inspection_location.push((sd!(Value::from("region")), Value::Text(region)));
        }
        if let Some(postal_code) = self.inspection_location.postal_code {
            inspection_location.push((sd!(Value::from("postal_code")), Value::Text(postal_code)));
        }
        map.push((CwtLabel::InspectionLocation.into(), Value::Map(inspection_location)));

        Ok(Value::Map(map))
    }
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct NestedPayload {
    pub nested: Vec<PayloadLog>,
}

impl serde::Serialize for NestedPayload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(&CwtLabel::NestedPayload, &self.nested)?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for NestedPayload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        // I'm lazy to go with a visitor
        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        let values = value.into_map().map_err(|_| D::Error::custom("expected a map"))?;

        let mut builder = NestedPayloadBuilder::create_empty();

        for entry in values {
            match entry {
                (Value::Integer(i), Value::Array(values)) if i == CwtLabel::NestedPayload => {
                    let values = values.into_iter().filter(|v| !matches!(v, Value::Tag(_, _))).collect::<Vec<_>>();
                    builder.nested(Value::Array(values).deserialized().map_err(D::Error::custom)?)
                }
                _ => unreachable!("Unexpected claim"),
            };
        }

        builder.build().map_err(D::Error::custom)
    }
}

impl Select for NestedPayload {
    fn select(self) -> Result<Value, ciborium::value::Error> {
        let mut map = Vec::with_capacity(1);

        let nested = self.nested.into_iter().map(|n| sd!(n.select().unwrap())).collect::<Vec<_>>();

        map.push((CwtLabel::NestedPayload.into(), Value::Array(nested)));
        Ok(Value::Map(map))
    }
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct PayloadLog {
    pub most_recent_inspection_passed: bool,
    #[builder(default, setter(into, strip_option))]
    pub inspector_license_number: Option<String>,
    pub inspection_date: u64,
    pub inspection_location: InspectionLocationNested,
}

impl serde::Serialize for PayloadLog {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(&CwtLabel::MostRecentInspectionPassed, &self.most_recent_inspection_passed)?;
        map.serialize_entry(&CwtLabel::InspectorLicenseNumber, &self.inspector_license_number)?;
        map.serialize_entry(&CwtLabel::InspectionDates, &self.inspection_date)?;
        let location = self.inspection_location.to_cbor_value().map_err(S::Error::custom)?;
        map.serialize_entry(&CwtLabel::InspectionLocation, &location)?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for PayloadLog {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        // I'm lazy to go with a visitor
        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        let values = value.into_map().map_err(|_| D::Error::custom("expected a map"))?;

        let mut builder = PayloadLogBuilder::create_empty();

        for entry in values {
            match entry {
                (Value::Integer(i), Value::Bool(b)) if i == CwtLabel::MostRecentInspectionPassed => builder.most_recent_inspection_passed(b),
                (Value::Integer(i), Value::Text(s)) if i == CwtLabel::InspectorLicenseNumber => builder.inspector_license_number(s),
                (Value::Integer(i), Value::Integer(d)) if i == CwtLabel::InspectionDates => builder.inspection_date(d.try_into().map_err(D::Error::custom)?),
                (Value::Integer(i), location) if i == CwtLabel::InspectionLocation => builder.inspection_location(location.deserialized().map_err(D::Error::custom)?),
                _ => unreachable!("Unexpected claim"),
            };
        }

        builder.build().map_err(D::Error::custom)
    }
}

impl Select for PayloadLog {
    fn select(self) -> Result<Value, ciborium::value::Error> {
        let mut map = Vec::with_capacity(4);

        map.push((CwtLabel::MostRecentInspectionPassed.into(), Value::Bool(self.most_recent_inspection_passed)));

        if let Some(inspector_license_number) = self.inspector_license_number {
            map.push((sd!(CwtLabel::InspectorLicenseNumber as i64), Value::Text(inspector_license_number)));
        }

        map.push((CwtLabel::InspectionDates.into(), Value::Integer(self.inspection_date.into())));

        let mut inspection_location = vec![(CwtLabel::NestedCountry.into(), Value::Text(self.inspection_location.country))];
        if let Some(region) = self.inspection_location.region {
            inspection_location.push((sd!(CwtLabel::NestedRegion as i64), Value::Text(region)));
        }
        if let Some(postal_code) = self.inspection_location.postal_code {
            inspection_location.push((sd!(CwtLabel::NestedPostalCode as i64), Value::Text(postal_code)));
        }
        map.push((sd!(Value::Integer((CwtLabel::InspectionLocation as i64).into())), Value::Map(inspection_location)));

        Ok(Value::Map(map))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize)]
pub struct InspectionLocation {
    pub country: String,
    pub region: Option<String>,
    pub postal_code: Option<String>,
}

impl<'de> serde::Deserialize<'de> for InspectionLocation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        let values = value.into_map().map_err(|_| D::Error::custom("expected a map"))?;

        let (mut country, mut region, mut postal_code) = (None, None, None);

        for entry in values {
            match entry {
                (Value::Text(k), Value::Text(v)) if k == "country" => country = Some(v),
                (Value::Text(k), Value::Text(v)) if k == "region" => region = Some(v),
                (Value::Text(k), Value::Text(v)) if k == "postal_code" => postal_code = Some(v),
                _ => {}
            };
        }

        Ok(Self {
            country: country.ok_or_else(|| D::Error::missing_field("country"))?,
            region,
            postal_code,
        })
    }
}

/// A bit different, labels are integers here to adapt to test vectors
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct InspectionLocationNested {
    pub country: String,
    pub region: Option<String>,
    pub postal_code: Option<String>,
}

impl serde::Serialize for InspectionLocationNested {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1 + self.region.is_some() as usize + self.postal_code.is_some() as usize))?;
        map.serialize_entry(&CwtLabel::NestedCountry, &self.country)?;
        if let Some(region) = &self.region {
            map.serialize_entry(&CwtLabel::NestedRegion, &region)?;
        }
        if let Some(postal_code) = &self.postal_code {
            map.serialize_entry(&CwtLabel::NestedPostalCode, &postal_code)?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for InspectionLocationNested {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        let values = value.into_map().map_err(|_| D::Error::custom("expected a map"))?;

        let (mut country, mut region, mut postal_code) = (None, None, None);

        for entry in values {
            match entry {
                (Value::Integer(i), Value::Text(v)) if i == CwtLabel::NestedCountry => country = Some(v),
                (Value::Integer(i), Value::Text(v)) if i == CwtLabel::NestedRegion => region = Some(v),
                (Value::Integer(i), Value::Text(v)) if i == CwtLabel::NestedPostalCode => postal_code = Some(v),
                _ => {}
            };
        }

        Ok(Self {
            country: country.ok_or_else(|| D::Error::missing_field("country"))?,
            region,
            postal_code,
        })
    }
}

/// Payload of "decoy.cbor"
#[derive(Debug, Clone, PartialEq)]
pub struct DecoyPayload {
    pub countries: Vec<String>,
    pub most_recent_inspection_passed: Option<bool>,
}

impl serde::Serialize for DecoyPayload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1 + self.most_recent_inspection_passed.is_some() as usize))?;
        map.serialize_entry(&CwtLabel::Countries, &self.countries)?;
        if let Some(most_recent_inspection_passed) = &self.most_recent_inspection_passed {
            map.serialize_entry(&CwtLabel::MostRecentInspectionPassed, most_recent_inspection_passed)?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for DecoyPayload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        let values = value.into_map().map_err(|_| D::Error::custom("expected a map"))?;

        let (mut countries, mut most_recent_inspection_passed) = (vec![], None);

        for entry in values {
            match entry {
                (Value::Integer(i), Value::Array(values)) if i == CwtLabel::Countries => {
                    // filters out the redacted elements
                    countries = values.into_iter().filter_map(|v| v.into_text().ok()).collect();
                }
                (Value::Integer(i), Value::Bool(b)) if i == CwtLabel::MostRecentInspectionPassed => most_recent_inspection_passed = Some(b),
                // the redacted claims
                (Value::Simple(_), _) => {}
                _ => unreachable!("Unexpected claim"),
            };
        }

        Ok(Self {
            countries,
            most_recent_inspection_passed,
        })
    }
}

impl Select for DecoyPayload {
    fn select(self) -> Result<Value, ciborium::value::Error> {
        // redacts each country and adds a decoy to hide the number of countries
        let mut countries = self.countries.into_iter().map(|c| sd!(c)).collect::<Vec<_>>();
        countries.push(decoy!(1));

        let mut map = vec![(CwtLabel::Countries.into(), Value::Array(countries))];
        if let Some(most_recent_inspection_passed) = self.most_recent_inspection_passed {
            map.push((sd!(CwtLabel::MostRecentInspectionPassed as i64), Value::Bool(most_recent_inspection_passed)));
        }
        // and a decoy in the payload
        map.push((decoy!(2), Value::Null));

        Ok(Value::Map(map))
    }
}
