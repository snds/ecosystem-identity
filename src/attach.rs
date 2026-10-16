//! The crate's front door: [`Identity`]. Create one, attach to one that is
//! already on the device (spec §6 steps 2, 4, 5), recover one from the kit,
//! then wrap and unwrap app keys under a persona.
//!
//! Two keys are derived rather than stored, so holding the IRK is holding
//! them: the Identity Signing Key (`HKDF(IRK, "…/isk/v1")`) and each
//! persona's receiving key (`HKDF(PK, "…/persona-kem/v1" ‖ persona_id)`).

use std::path::Path;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::auth::AccountAuth;
use crate::kdf;
use crate::kem::{self, DEFAULT_KEM, KemSecretKey};
use crate::keys::{self, AppDataKey, CrownJewelKey, Irk, PersonaKey, SymmetricKey};
use crate::keystore::DeviceKeystore;
use crate::kit::RecoveryKit;
use crate::records::{
    Consent, Device, EnrolledBy, Id, KeyEnvelope, KeyRef, KeyRefKind, Persona, PersonaKind,
    Profile, Purpose, RECORD_V, Record, RecoveryState, Timestamp,
};
use crate::store::{Contents, FORMAT, FORMAT_MAJOR, Head, Probe, Store};
use crate::{Error, Result};

const ISK_INFO: &[u8] = b"ecosystem-identity/isk/v1";
const PERSONA_KEM_INFO: &[u8] = b"ecosystem-identity/persona-kem/v1";
/// The label of the persona every identity starts with.
pub const FIRST_PERSONA_LABEL: &str = "Personal";

/// The Identity Signing Key that `irk` derives. Holding the IRK is holding
/// the ISK; this is how a manager that has just attached signs the profile.
pub fn signing_key(irk: &Irk) -> Result<SigningKey> {
    let seed = kdf::subkey(irk.expose(), ISK_INFO)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// The seed of a persona's receiving key: derived from the Persona Key and
/// the persona id, so it needs no envelope of its own.
pub fn persona_kem_seed(pk: &PersonaKey, persona_id: Id) -> Result<[u8; 32]> {
    let mut info = PERSONA_KEM_INFO.to_vec();
    info.extend_from_slice(persona_id.as_bytes());
    Ok(*kdf::subkey(pk.expose(), &info)?)
}

/// What attaching to a root found.
#[derive(Debug)]
pub enum Attach {
    /// This device holds a wrap of the IRK and it opened.
    Attached(Box<Identity>),
    /// No identity at this root (§6 step 5: create one).
    Nothing,
    /// A profile exists but this device is not enrolled in it (§6 step 3 or
    /// §8 rows 2 and 3 apply). The records are readable; the keys are not.
    NotEnrolled {
        /// The profile that is there.
        profile: Profile,
    },
}

/// What opening the account slot needs: the login, the password, and the
/// Secret Key from the kit (`None` is the documented opt-out).
pub struct AccountCredentials<'a> {
    /// The account login (OPAQUE, or the local stub).
    pub auth: &'a mut dyn AccountAuth,
    /// The master password.
    pub password: &'a str,
    /// The kit's Secret Key, when the person has one.
    pub secret_key: Option<&'a [u8; 16]>,
}

/// The identity, open: the IRK is in memory until this is dropped.
pub struct Identity {
    store: Store,
    contents: Contents,
    head: Head,
    irk: Irk,
    isk: SigningKey,
    device_id: Id,
    app: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("root", &self.store.root())
            .field("device", &self.device_id)
            .field("app", &self.app)
            .finish_non_exhaustive()
    }
}

/// Everything about an identity that is not tied to one device: what a
/// server or a backup keeps so the kit can rebuild it elsewhere (§8 row 3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Backup {
    /// The store format the records were written under.
    pub format: String,
    /// The profile.
    pub profile: Profile,
    /// Every persona.
    pub personas: Vec<Persona>,
    /// Every device, including revoked ones.
    pub devices: Vec<Device>,
    /// Every envelope except the device wraps, which only their device can open.
    pub envelopes: Vec<KeyEnvelope>,
    /// Every consent.
    pub consents: Vec<Consent>,
}

impl Backup {
    /// As canonical CBOR.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        crate::cbor::to_canonical(self)
    }

    /// From CBOR.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        crate::cbor::from_slice(bytes)
    }
}

impl Identity {
    /// Creates a new identity at `root` with the first persona, this device
    /// enrolled, and `manager` none (§6 step 5). `app` is the creating app's
    /// id; it is recorded on the persona. The recovery kit is a separate step.
    pub fn create(
        root: &Path,
        app: &str,
        device_name: &str,
        keystore: &dyn DeviceKeystore,
    ) -> Result<Identity> {
        let store = Store::at(root);
        store.init()?;
        let irk = Irk::generate()?;
        let irk_id = Id::new();
        let isk = signing_key(&irk)?;
        let profile_id = Id::new();
        let now = Timestamp::now();

        let mut profile = Profile {
            v: RECORD_V,
            profile_id,
            created_at: now,
            recovery: RecoveryState::None,
            manager: None,
            format_v: FORMAT_MAJOR,
            isk_pub: isk.verifying_key().to_bytes(),
            kdf: kdf::calibrate(Duration::from_secs(1))?,
            extra: Default::default(),
            sig: Vec::new(),
        };
        profile.sign(&isk)?;

        let mut contents = Contents {
            profile: Some(profile),
            ..Default::default()
        };
        let mut identity = Identity {
            store,
            contents: Contents::default(),
            head: Head::new(0, [0; 32]),
            irk,
            isk,
            device_id: keystore.device_id(),
            app: app.to_string(),
        };

        let device = identity.device_record(device_name, keystore, EnrolledBy::Creator)?;
        contents.devices.insert(device.device_id, device);
        contents.put_envelope(identity.device_wrap(profile_id, irk_id, keystore)?);
        identity.contents = contents;
        identity.add_persona(FIRST_PERSONA_LABEL, PersonaKind::Personal, irk_id)?;
        identity.commit()?;
        Ok(identity)
    }

    /// Probes `root` and, if an identity is there and this device is enrolled,
    /// opens it with the device unlock and no kit (§6 steps 2 and 4).
    /// `remembered` is the head this device last accepted; a store behind it
    /// is refused as a rollback, and a profile whose password-stretching
    /// parameters are below the ones that head remembers is refused too
    /// (they only ever rise; D26).
    pub fn attach(
        root: &Path,
        app: &str,
        keystore: &dyn DeviceKeystore,
        remembered: Option<Head>,
    ) -> Result<Attach> {
        let store = Store::at(root);
        if store.probe()? == Probe::Missing {
            return Ok(Attach::Nothing);
        }
        let loaded = store.load()?;
        if let Some(seen) = remembered {
            check_against_remembered(&seen, &loaded)?;
        }
        let profile = loaded.contents.profile()?.clone();
        let device_ref = KeyRef::new(KeyRefKind::Device, keystore.device_id());
        let Some(envelope) = loaded
            .contents
            .envelopes
            .values()
            .find(|e| e.purpose == Purpose::Irk && e.wrapped_by == device_ref)
            .cloned()
        else {
            return Ok(Attach::NotEnrolled { profile });
        };
        if loaded
            .contents
            .devices
            .get(&keystore.device_id())
            .is_some_and(|d| d.revoked_at.is_some())
        {
            return Err(Error::Invalid(
                "this device was revoked from the identity".into(),
            ));
        }
        let unlock = keystore.unlock()?;
        let irk: Irk = keys::unwrap_key(
            &envelope,
            &unlock,
            &keys::aad(profile.profile_id, None, envelope.key_id, Purpose::Irk),
        )?;
        let isk = signing_key(&irk)?;
        if isk.verifying_key().to_bytes() != profile.isk_pub {
            return Err(Error::BadSignature(
                "profile (its signing key isn't the one this root key derives)".into(),
            ));
        }
        Ok(Attach::Attached(Box::new(Identity {
            store,
            contents: loaded.contents,
            head: loaded.head,
            irk,
            isk,
            device_id: keystore.device_id(),
            app: app.to_string(),
        })))
    }

    /// Steps 2, 4, and 5 of §6 in one call: attach if this device can, create
    /// if nothing is there. A profile this device is not enrolled in is an
    /// error here, because the answer is another device or the kit.
    pub fn open_or_create(
        root: &Path,
        app: &str,
        device_name: &str,
        keystore: &dyn DeviceKeystore,
        remembered: Option<Head>,
    ) -> Result<Identity> {
        match Self::attach(root, app, keystore, remembered)? {
            Attach::Attached(identity) => Ok(*identity),
            Attach::Nothing => Self::create(root, app, device_name, keystore),
            Attach::NotEnrolled { .. } => Err(Error::DeviceNotEnrolled),
        }
    }

    /// Rebuilds the identity at an empty `root` from the kit and a backup
    /// (§8 row 3), and enrols this device.
    pub fn recover_with_kit(
        root: &Path,
        app: &str,
        device_name: &str,
        keystore: &dyn DeviceKeystore,
        kit: &RecoveryKit,
        backup: &Backup,
    ) -> Result<Identity> {
        let profile = &backup.profile;
        if kit.profile_id() != profile.profile_id {
            return Err(Error::KitRejected);
        }
        let kit_ref = KeyRef::new(KeyRefKind::Kit, profile.profile_id);
        let Some(envelope) = backup
            .envelopes
            .iter()
            .find(|e| e.purpose == Purpose::Irk && e.wrapped_by == kit_ref)
        else {
            return Err(Error::NotFound(
                "a kit wrap of the root key in the backup".into(),
            ));
        };
        let kit_key = kit.kit_key(&profile.kdf)?;
        let irk: Irk = keys::unwrap_key(
            envelope,
            &kit_key,
            &keys::aad(profile.profile_id, None, envelope.key_id, Purpose::Irk),
        )
        .map_err(|_| Error::KitRejected)?;
        Self::restore(
            root,
            app,
            device_name,
            keystore,
            irk,
            envelope.key_id,
            backup,
            EnrolledBy::Kit,
        )
    }

    /// Opens the identity on a new device with the account password and the
    /// Secret Key (04-security §3), from a backup, and enrols the device.
    pub fn recover_with_account(
        root: &Path,
        app: &str,
        device_name: &str,
        keystore: &dyn DeviceKeystore,
        account: AccountCredentials<'_>,
        backup: &Backup,
    ) -> Result<Identity> {
        let profile = &backup.profile;
        let account_ref = KeyRef::new(KeyRefKind::Account, profile.profile_id);
        let Some(envelope) = backup
            .envelopes
            .iter()
            .find(|e| e.purpose == Purpose::Irk && e.wrapped_by == account_ref)
        else {
            return Err(Error::NotFound(
                "an account wrap of the root key in the backup".into(),
            ));
        };
        let export_key = account.auth.login(&profile.profile_id, account.password)?;
        let auk =
            kdf::account_unlock_key(export_key.expose(), account.secret_key, &profile.profile_id)?;
        let irk: Irk = keys::unwrap_key(
            envelope,
            &auk,
            &keys::aad(profile.profile_id, None, envelope.key_id, Purpose::Irk),
        )?;
        Self::restore(
            root,
            app,
            device_name,
            keystore,
            irk,
            envelope.key_id,
            backup,
            EnrolledBy::Kit,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn restore(
        root: &Path,
        app: &str,
        device_name: &str,
        keystore: &dyn DeviceKeystore,
        irk: Irk,
        irk_id: Id,
        backup: &Backup,
        enrolled_by: EnrolledBy,
    ) -> Result<Identity> {
        let store = Store::at(root);
        if !store.is_empty()? {
            return Err(Error::Invalid(format!(
                "{} isn't empty; recovery needs an empty root",
                root.display()
            )));
        }
        if backup.format != FORMAT {
            return Err(Error::FormatUnknown(backup.format.clone()));
        }
        let isk = signing_key(&irk)?;
        let verifying = isk.verifying_key();
        if verifying.to_bytes() != backup.profile.isk_pub {
            return Err(Error::KitRejected);
        }
        backup.profile.verify(&verifying)?;
        backup.profile.kdf.check_floor()?;
        let mut contents = Contents {
            profile: Some(backup.profile.clone()),
            ..Default::default()
        };
        for p in &backup.personas {
            p.verify(&verifying)?;
            contents.personas.insert(p.persona_id, p.clone());
        }
        for d in &backup.devices {
            d.verify(&verifying)?;
            contents.devices.insert(d.device_id, d.clone());
        }
        for e in &backup.envelopes {
            e.verify(&verifying)?;
            contents.put_envelope(e.clone());
        }
        for c in &backup.consents {
            c.verify(&verifying)?;
            contents.consents.insert(c.file_name(), c.clone());
        }
        store.init()?;
        let mut identity = Identity {
            store,
            contents,
            head: Head::new(0, [0; 32]),
            irk,
            isk,
            device_id: keystore.device_id(),
            app: app.to_string(),
        };
        let device = identity.device_record(device_name, keystore, enrolled_by)?;
        identity.contents.devices.insert(device.device_id, device);
        let wrap = identity.device_wrap(backup.profile.profile_id, irk_id, keystore)?;
        identity.contents.put_envelope(wrap);
        identity.commit()?;
        Ok(identity)
    }

    /// What a server or a backup should keep (§8 row 3, §11 open question).
    pub fn export_backup(&self) -> Backup {
        Backup {
            format: FORMAT.to_string(),
            profile: self.profile().clone(),
            personas: self.contents.personas.values().cloned().collect(),
            devices: self.contents.devices.values().cloned().collect(),
            envelopes: self
                .contents
                .envelopes
                .values()
                .filter(|e| e.wrapped_by.kind != KeyRefKind::Device)
                .cloned()
                .collect(),
            consents: self.contents.consents.values().cloned().collect(),
        }
    }

    /// Makes the recovery kit and the `kit` wrap of the IRK; `recovery`
    /// becomes `created`. The caller shows the kit once and forgets it.
    pub fn create_recovery_kit(&mut self) -> Result<RecoveryKit> {
        self.check_profile_writable()?;
        let profile_id = self.profile().profile_id;
        let kit = RecoveryKit::generate(profile_id)?;
        let kit_key = kit.kit_key(&self.profile().kdf)?;
        let irk_id = self.irk_id()?;
        let mut envelope = keys::wrap(
            self.irk.expose(),
            &kit_key,
            KeyRef::new(KeyRefKind::Kit, profile_id),
            &keys::aad(profile_id, None, irk_id, Purpose::Irk),
        )?;
        envelope.sign(&self.isk)?;
        self.contents.put_envelope(envelope);
        let mut profile = self.profile().clone();
        profile.recovery = RecoveryState::Created;
        profile.sign(&self.isk)?;
        self.contents.profile = Some(profile);
        self.commit()?;
        Ok(kit)
    }

    /// Registers the password with `auth` and writes the `account` wrap of
    /// the IRK under the Account Unlock Key (04-security §3). `secret_key`
    /// is the kit's; `None` is the documented opt-out.
    pub fn enable_account_unlock(
        &mut self,
        auth: &mut dyn AccountAuth,
        password: &str,
        secret_key: Option<&[u8; 16]>,
    ) -> Result<()> {
        self.check_profile_writable()?;
        let profile_id = self.profile().profile_id;
        let export_key = auth.register(&profile_id, password)?;
        let auk = kdf::account_unlock_key(export_key.expose(), secret_key, &profile_id)?;
        let irk_id = self.irk_id()?;
        let mut envelope = keys::wrap(
            self.irk.expose(),
            &auk,
            KeyRef::new(KeyRefKind::Account, profile_id),
            &keys::aad(profile_id, None, irk_id, Purpose::Irk),
        )?;
        envelope.sign(&self.isk)?;
        self.contents.put_envelope(envelope);
        self.commit()
    }

    /// Records that the kit was tried and opened the identity (04-security §9).
    pub fn mark_recovery_drilled(&mut self) -> Result<()> {
        self.check_profile_writable()?;
        if self.profile().recovery == RecoveryState::None {
            return Err(Error::Invalid(
                "make the recovery kit before drilling it".into(),
            ));
        }
        let mut profile = self.profile().clone();
        profile.recovery = RecoveryState::Drilled;
        profile.sign(&self.isk)?;
        self.contents.profile = Some(profile);
        self.commit()
    }

    /// The profile.
    pub fn profile(&self) -> &Profile {
        self.contents
            .profile
            .as_ref()
            .expect("an open identity has a profile")
    }

    /// Every persona.
    pub fn personas(&self) -> impl Iterator<Item = &Persona> {
        self.contents.personas.values()
    }

    /// Every device.
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.contents.devices.values()
    }

    /// Every envelope, for inspection and the conformance suite.
    pub fn envelopes(&self) -> impl Iterator<Item = &KeyEnvelope> {
        self.contents.envelopes.values()
    }

    /// Every consent.
    pub fn consents(&self) -> impl Iterator<Item = &Consent> {
        self.contents.consents.values()
    }

    /// This device's id.
    pub fn device_id(&self) -> Id {
        self.device_id
    }

    /// The app this identity was opened as.
    pub fn app(&self) -> &str {
        &self.app
    }

    /// The root on disk.
    pub fn root(&self) -> &Path {
        self.store.root()
    }

    /// The newest manifest head. Keep it and pass it to the next `attach`.
    pub fn head(&self) -> Head {
        self.head
    }

    /// The IRK's key id, read from this device's wrap of it.
    pub fn irk_id(&self) -> Result<Id> {
        self.contents
            .envelopes
            .values()
            .find(|e| e.purpose == Purpose::Irk)
            .map(|e| e.key_id)
            .ok_or_else(|| Error::NotFound("a wrap of the root key".into()))
    }

    /// Adds a persona (D13). The persona's key is wrapped to the IRK; its
    /// receiving key is derived from that key.
    pub fn create_persona(&mut self, label: &str, kind: PersonaKind) -> Result<Persona> {
        let irk_id = self.irk_id()?;
        let persona = self.add_persona(label, kind, irk_id)?;
        self.commit()?;
        Ok(persona)
    }

    /// The Persona Key, if this identity may open it.
    pub fn persona_key(&self, persona_id: Id) -> Result<PersonaKey> {
        let persona = self.persona(persona_id)?;
        let envelope = self.envelope(persona_id, persona.identity_key_ref)?;
        keys::unwrap_key(
            envelope,
            &self.irk,
            &keys::aad(
                self.profile().profile_id,
                Some(persona_id),
                persona_id,
                Purpose::Persona,
            ),
        )
    }

    /// The private half of a persona's receiving key.
    pub fn persona_kem_secret(&self, persona_id: Id) -> Result<KemSecretKey> {
        let pk = self.persona_key(persona_id)?;
        let alg = self.persona(persona_id)?.kem_pub.alg;
        Ok(kem::kem(alg).keypair(persona_kem_seed(&pk, persona_id)?)?.0)
    }

    /// Wraps `app`'s data key under a persona and returns its key id. The
    /// app label is sealed into the envelope, so it opens only when asked
    /// for as that app (D28). Every app-level key must be wrapped this way
    /// from the start, or the kit cannot reach that app's data (D11).
    pub fn wrap_app_key(&mut self, persona_id: Id, app: &str, key: &AppDataKey) -> Result<Id> {
        check_app_label(app)?;
        self.wrap_under_persona(persona_id, app, key.expose(), Purpose::AppData)
    }

    /// Opens `app`'s data key by its key id. An envelope that carries
    /// another app's label is refused by name, before any decryption.
    pub fn unwrap_app_key(&self, persona_id: Id, app: &str, key_id: Id) -> Result<AppDataKey> {
        self.unwrap_under_persona(persona_id, app, key_id, Purpose::AppData)
    }

    /// The key ids of every data key `app` has wrapped under a persona,
    /// oldest first.
    pub fn app_keys(&self, persona_id: Id, app: &str) -> Vec<Id> {
        let persona_ref = KeyRef::new(KeyRefKind::Persona, persona_id);
        let mut found: Vec<&KeyEnvelope> = self
            .contents
            .envelopes
            .values()
            .filter(|e| {
                e.purpose == Purpose::AppData && e.wrapped_by == persona_ref && e.app == app
            })
            .collect();
        found.sort_by_key(|e| (e.created_at, e.key_id));
        found.into_iter().map(|e| e.key_id).collect()
    }

    /// Wraps a persona's Crown-Jewel Key for `app`. The fresh-biometric and
    /// deliberate-tap rules around using it belong to the app (§3).
    pub fn wrap_crown_jewel_key(
        &mut self,
        persona_id: Id,
        app: &str,
        key: &CrownJewelKey,
    ) -> Result<Id> {
        check_app_label(app)?;
        self.wrap_under_persona(persona_id, app, key.expose(), Purpose::CrownJewel)
    }

    /// Opens a persona's Crown-Jewel Key that `app` wrapped.
    pub fn unwrap_crown_jewel_key(
        &self,
        persona_id: Id,
        app: &str,
        key_id: Id,
    ) -> Result<CrownJewelKey> {
        self.unwrap_under_persona(persona_id, app, key_id, Purpose::CrownJewel)
    }

    /// Removes an envelope from the store (D29). The file goes; the
    /// manifest records a tombstone for it, so the chain still explains the
    /// removal and a copy of the file put back is refused as unlisted; the
    /// head advances. The key inside is gone for good unless another wrap
    /// of it exists.
    pub fn retire_envelope(&mut self, key_id: Id, wrapped_by: KeyRef) -> Result<()> {
        let name = format!("{key_id}.{wrapped_by}.cbor");
        if self.contents.envelopes.remove(&name).is_none() {
            return Err(Error::NotFound(format!(
                "an envelope for key {key_id} opened by {wrapped_by}"
            )));
        }
        self.commit()
    }

    /// Hands management to `manager` (§7). Sets `Profile.manager`, signs the
    /// profile, and changes nothing else: no move, no re-encryption.
    pub fn adopt(&mut self, manager: &str) -> Result<()> {
        if manager.trim().is_empty() {
            return Err(Error::Invalid("a manager needs a name".into()));
        }
        self.check_profile_writable()?;
        let mut profile = self.profile().clone();
        profile.manager = Some(manager.to_string());
        profile.sign(&self.isk)?;
        self.contents.profile = Some(profile);
        self.commit()
    }

    /// Sets `manager` back to none (§7). Only the manager may.
    pub fn unlink(&mut self) -> Result<()> {
        self.check_profile_writable()?;
        let mut profile = self.profile().clone();
        profile.manager = None;
        profile.sign(&self.isk)?;
        self.contents.profile = Some(profile);
        self.commit()
    }

    /// Records a tolerated-tier grant the person gave on this device.
    pub fn record_consent(&mut self, bridge: &str, disclosure_version: u32) -> Result<Consent> {
        if bridge.is_empty() || bridge.contains(['/', '\\', '.']) {
            return Err(Error::Invalid(
                "a bridge id is a plain name without slashes or dots".into(),
            ));
        }
        let mut consent = Consent {
            v: RECORD_V,
            bridge: bridge.to_string(),
            disclosure_version,
            granted_at: Timestamp::now(),
            device_id: self.device_id,
            extra: Default::default(),
            sig: Vec::new(),
        };
        consent.sign(&self.isk)?;
        self.contents
            .consents
            .insert(consent.file_name(), consent.clone());
        self.commit()?;
        Ok(consent)
    }

    /// Re-reads and re-verifies the store, so changes another app wrote on
    /// this device show up. Refuses a rollback behind the head seen last,
    /// and a lowering of the password-stretching parameters (D26).
    pub fn refresh(&mut self) -> Result<()> {
        let loaded = self.store.load()?;
        check_against_remembered(&self.head, &loaded)?;
        self.contents = loaded.contents;
        self.head = loaded.head;
        Ok(())
    }

    /// The last step of a local handshake on the new device (spec §6 step
    /// 3): this device holds the IRK it was handed, and the running app has
    /// already written this device's record. Writes this device's own wrap
    /// of the IRK under its keystore key, then attaches the ordinary way.
    /// `granted` is the head the running app reported; a store behind it is
    /// refused.
    pub(crate) fn finish_enrolment(
        root: &Path,
        app: &str,
        keystore: &dyn DeviceKeystore,
        irk: Irk,
        irk_id: Id,
        granted: Head,
    ) -> Result<Identity> {
        let store = Store::at(root);
        let loaded = store.load()?;
        check_against_remembered(&granted, &loaded)?;
        let profile = loaded.contents.profile()?.clone();
        let isk = signing_key(&irk)?;
        if isk.verifying_key().to_bytes() != profile.isk_pub {
            return Err(Error::BadSignature(
                "profile (the root key handed over doesn't derive its signing key)".into(),
            ));
        }
        match loaded.contents.devices.get(&keystore.device_id()) {
            None => {
                return Err(Error::Handshake(
                    "the running app didn't record this device".into(),
                ));
            }
            Some(d) if d.revoked_at.is_some() => {
                return Err(Error::Invalid(
                    "this device was revoked from the identity".into(),
                ));
            }
            Some(_) => {}
        }
        let mut identity = Identity {
            store,
            contents: loaded.contents,
            head: loaded.head,
            irk,
            isk,
            device_id: keystore.device_id(),
            app: app.to_string(),
        };
        let wrap = identity.device_wrap(profile.profile_id, irk_id, keystore)?;
        identity.contents.put_envelope(wrap);
        identity.commit()?;
        let head = identity.head;
        drop(identity);
        match Self::attach(root, app, keystore, Some(head))? {
            Attach::Attached(identity) => Ok(*identity),
            Attach::Nothing => Err(Error::NoIdentity(root.display().to_string())),
            Attach::NotEnrolled { .. } => Err(Error::DeviceNotEnrolled),
        }
    }

    /// The root key. For the handshake's wrap to a new device; never
    /// leaves the crate.
    pub(crate) fn irk(&self) -> &Irk {
        &self.irk
    }

    /// The signing key. For the handshake, which signs the new device's
    /// record and the envelope it hands over.
    pub(crate) fn isk(&self) -> &SigningKey {
        &self.isk
    }

    /// Adds a device record another device asked to enrol and commits.
    /// The record must already be signed.
    pub(crate) fn add_device(&mut self, device: Device) -> Result<()> {
        self.contents.devices.insert(device.device_id, device);
        self.commit()
    }

    fn persona(&self, persona_id: Id) -> Result<&Persona> {
        self.contents
            .personas
            .get(&persona_id)
            .ok_or_else(|| Error::NotFound(format!("persona {persona_id}")))
    }

    fn envelope(&self, key_id: Id, wrapped_by: KeyRef) -> Result<&KeyEnvelope> {
        self.contents
            .envelopes
            .get(&format!("{key_id}.{wrapped_by}.cbor"))
            .ok_or_else(|| {
                Error::NotFound(format!(
                    "an envelope for key {key_id} opened by {wrapped_by}"
                ))
            })
    }

    fn wrap_under_persona(
        &mut self,
        persona_id: Id,
        app: &str,
        secret: &[u8],
        purpose: Purpose,
    ) -> Result<Id> {
        let pk = self.persona_key(persona_id)?;
        let key_id = Id::new();
        let mut envelope = keys::wrap(
            secret,
            &pk,
            KeyRef::new(KeyRefKind::Persona, persona_id),
            &keys::app_aad(self.profile().profile_id, persona_id, key_id, purpose, app),
        )?;
        envelope.sign(&self.isk)?;
        self.contents.put_envelope(envelope);
        self.commit()?;
        Ok(key_id)
    }

    fn unwrap_under_persona<K: SymmetricKey>(
        &self,
        persona_id: Id,
        app: &str,
        key_id: Id,
        purpose: Purpose,
    ) -> Result<K> {
        let pk = self.persona_key(persona_id)?;
        let envelope = self.envelope(key_id, KeyRef::new(KeyRefKind::Persona, persona_id))?;
        keys::unwrap_key(
            envelope,
            &pk,
            &keys::app_aad(self.profile().profile_id, persona_id, key_id, purpose, app),
        )
    }

    fn add_persona(&mut self, label: &str, kind: PersonaKind, irk_id: Id) -> Result<Persona> {
        let profile_id = self.profile().profile_id;
        let persona_id = Id::new();
        let pk = PersonaKey::generate()?;
        let (_, kem_pub) = kem::kem(DEFAULT_KEM).keypair(persona_kem_seed(&pk, persona_id)?)?;
        let identity_key_ref = KeyRef::new(KeyRefKind::Irk, irk_id);
        let mut envelope = keys::wrap(
            pk.expose(),
            &self.irk,
            identity_key_ref,
            &keys::aad(profile_id, Some(persona_id), persona_id, Purpose::Persona),
        )?;
        envelope.sign(&self.isk)?;
        let mut persona = Persona {
            v: RECORD_V,
            persona_id,
            label: label.to_string(),
            kind,
            created_by_app: self.app.clone(),
            identity_key_ref,
            kem_pub,
            color: None,
            extra: Default::default(),
            sig: Vec::new(),
        };
        persona.sign(&self.isk)?;
        self.contents.put_envelope(envelope);
        self.contents.personas.insert(persona_id, persona.clone());
        Ok(persona)
    }

    fn device_record(
        &self,
        name: &str,
        keystore: &dyn DeviceKeystore,
        enrolled_by: EnrolledBy,
    ) -> Result<Device> {
        let mut device = Device {
            v: RECORD_V,
            device_id: keystore.device_id(),
            name: name.to_string(),
            platform: keystore.platform(),
            attestation: keystore.attestation(),
            device_pub: keystore.device_pub(),
            kem_pub: keystore.kem_pub(),
            enrolled_at: Timestamp::now(),
            enrolled_by,
            revoked_at: None,
            extra: Default::default(),
            sig: Vec::new(),
        };
        device.sign(&self.isk)?;
        Ok(device)
    }

    fn device_wrap(
        &self,
        profile_id: Id,
        irk_id: Id,
        keystore: &dyn DeviceKeystore,
    ) -> Result<KeyEnvelope> {
        let unlock = keystore.unlock()?;
        let mut envelope = keys::wrap(
            self.irk.expose(),
            &unlock,
            KeyRef::new(KeyRefKind::Device, keystore.device_id()),
            &keys::aad(profile_id, None, irk_id, Purpose::Irk),
        )?;
        envelope.sign(&self.isk)?;
        Ok(envelope)
    }

    /// The profile may be written by the manager, or by any app while there
    /// is none (§2).
    fn check_profile_writable(&self) -> Result<()> {
        match &self.profile().manager {
            Some(m) if m != &self.app => Err(Error::Invalid(format!(
                "this identity is managed by {m}; only it may change the profile"
            ))),
            _ => Ok(()),
        }
    }

    fn commit(&mut self) -> Result<()> {
        let (_, head) = self
            .store
            .write(&self.contents, &self.isk, self.device_id)?;
        self.head = head;
        Ok(())
    }
}

/// An app label is a plain id: not empty, no whitespace.
fn check_app_label(app: &str) -> Result<()> {
    if app.is_empty() || app.chars().any(char::is_whitespace) {
        return Err(Error::Invalid(
            "an app label is a plain id without spaces".into(),
        ));
    }
    Ok(())
}

/// The two checks a remembered head enables: no rollback of the manifest,
/// and no lowering of the password-stretching parameters (D26).
fn check_against_remembered(remembered: &Head, loaded: &crate::store::Loaded) -> Result<()> {
    if remembered.is_behind(&loaded.head) {
        return Err(Error::RolledBack {
            found: loaded.head.seq,
            remembered: remembered.seq,
        });
    }
    remembered.check_kdf_not_lowered(&loaded.contents.profile()?.kdf)
}
