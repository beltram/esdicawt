use insta::Snapshot;
use std::path::PathBuf;

#[derive(Debug, Copy, Clone, Eq, PartialEq, strum_macros::EnumIter)]
pub enum SdCwtSnapshots {
    Full,
    #[cfg(feature = "backward")]
    FullDraft08,
    Empty,
    #[cfg(feature = "backward")]
    EmptyDraft08,
    AllRedacted,
    #[cfg(feature = "backward")]
    AllRedactedDraft08,
    NoneRedacted,
    #[cfg(feature = "backward")]
    NoneRedactedDraft08,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, strum_macros::EnumIter)]
pub enum SdKbtSnapshots {
    Full,
    #[cfg(feature = "backward")]
    FullDraft08,
    None,
    #[cfg(feature = "backward")]
    NoneDraft08,
}

impl SdCwtSnapshots {
    fn file(&self) -> PathBuf {
        let s = match self {
            Self::Full => "src/snapshots/esdicawt__issuer__snapshot__sd-cwt-full-ed25519.txt.snap",
            Self::Empty => "src/snapshots/esdicawt__issuer__snapshot__sd-cwt-empty-ed25519.txt.snap",
            Self::AllRedacted => "src/snapshots/esdicawt__issuer__snapshot__sd-cwt-all-redacted-ed25519.txt.snap",
            Self::NoneRedacted => "src/snapshots/esdicawt__issuer__snapshot__sd-cwt-none-redacted-ed25519.txt.snap",
            #[cfg(feature = "backward")]
            Self::FullDraft08 => "src/snapshots/esdicawt__issuer__snapshot__sd-cwt-full-ed25519-draft08.txt.snap",
            #[cfg(feature = "backward")]
            Self::EmptyDraft08 => "src/snapshots/esdicawt__issuer__snapshot__sd-cwt-empty-ed25519-draft08.txt.snap",
            #[cfg(feature = "backward")]
            Self::AllRedactedDraft08 => "src/snapshots/esdicawt__issuer__snapshot__sd-cwt-all-redacted-ed25519-draft08.txt.snap",
            #[cfg(feature = "backward")]
            Self::NoneRedactedDraft08 => "src/snapshots/esdicawt__issuer__snapshot__sd-cwt-none-redacted-ed25519-draft08.txt.snap",
        };
        let path = PathBuf::from(s.to_string());
        assert!(path.exists());
        path
    }

    pub fn sd_cwt(&self) -> Vec<u8> {
        snapshot_from_file(self.file())
    }
}

impl SdKbtSnapshots {
    fn file(&self) -> PathBuf {
        let s = match self {
            Self::Full => "src/snapshots/esdicawt__holder__snapshot__sd-kbt-full-ed25519.txt.snap",
            Self::None => "src/snapshots/esdicawt__holder__snapshot__sd-kbt-none-ed25519.txt.snap",
            #[cfg(feature = "backward")]
            Self::FullDraft08 => "src/snapshots/esdicawt__holder__snapshot__sd-kbt-full-ed25519-draft08.txt.snap",
            #[cfg(feature = "backward")]
            Self::NoneDraft08 => "src/snapshots/esdicawt__holder__snapshot__sd-kbt-none-ed25519-draft08.txt.snap",
        };
        let path = PathBuf::from(s.to_string());
        assert!(path.exists());
        path
    }

    pub fn sd_kbt(&self) -> Vec<u8> {
        snapshot_from_file(self.file())
    }
}

fn snapshot_from_file(file: PathBuf) -> Vec<u8> {
    let file = file.canonicalize().unwrap();
    let snapshot = Snapshot::from_file(&file).unwrap();
    let snapshot = snapshot.contents().as_text().unwrap();
    hex::decode(snapshot.to_string()).unwrap()
}
