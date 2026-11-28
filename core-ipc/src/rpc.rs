//! Request ownership and response schemas, without retaining request secrets.

use core_types::{Daemon, EventKind};

macro_rules! contracts {
    // A `pat` fragment may be followed only by `=>`, `,`, `=`, `if`, or `in`.
    ($($kind:ident: $owner:ident, $request:pat => $response:pat),+ $(,)?) => {
        #[derive(Clone, Copy)]
        pub(crate) enum Rpc {
            ConfigStatus(Daemon),
            $($kind,)+
        }

        impl Rpc {
            pub(crate) fn of(event: &EventKind) -> Option<Self> {
                match event {
                    EventKind::ConfigStatusRequest { daemon } => Some(Self::ConfigStatus(*daemon)),
                    $($request => Some(Self::$kind),)+
                    _ => None,
                }
            }

            pub(crate) fn owner(self) -> Daemon {
                match self {
                    Self::ConfigStatus(daemon) => daemon,
                    $(Self::$kind => Daemon::$owner,)+
                }
            }

            pub(crate) fn accepts(self, event: &EventKind) -> bool {
                if matches!(event, EventKind::AccessDenied { .. }) {
                    return true;
                }
                match self {
                    Self::ConfigStatus(expected) => matches!(
                        event,
                        EventKind::ConfigStatusResponse { daemon, .. } if *daemon == expected
                    ),
                    $(Self::$kind => matches!(event, $response),)+
                }
            }

            pub(crate) fn is_response(event: &EventKind) -> bool {
                matches!(event, EventKind::AccessDenied { .. } | EventKind::ConfigStatusResponse { .. })
                    $(|| matches!(event, $response))+
            }
        }
    };
}

contracts! {
    Status: Profile, EventKind::StatusRequest => EventKind::StatusResponse { .. },
    ProfileList: Profile, EventKind::ProfileList => EventKind::ProfileListResponse { .. },
    ProfileActivate: Profile, EventKind::ProfileActivate { .. } => EventKind::ProfileActivateResponse { .. },
    ProfileDeactivate: Profile, EventKind::ProfileDeactivate { .. } => EventKind::ProfileDeactivateResponse { .. },
    SetDefaultProfile: Profile, EventKind::SetDefaultProfile { .. } => EventKind::SetDefaultProfileResponse { .. },
    KeyRotation: Profile, EventKind::KeyRotationRequest => EventKind::KeyRotationRequestResponse { .. },
    SecretGet: Secrets, EventKind::SecretGet { .. } => EventKind::SecretGetResponse { .. },
    SecretSet: Secrets, EventKind::SecretSet { .. } => EventKind::SecretSetResponse { .. },
    SecretDelete: Secrets, EventKind::SecretDelete { .. } => EventKind::SecretDeleteResponse { .. },
    SecretList: Secrets, EventKind::SecretList { .. } => EventKind::SecretListResponse { .. },
    SecretsState: Secrets, EventKind::SecretsStateRequest => EventKind::SecretsStateResponse { .. },
    FactorSubmit: Secrets, EventKind::FactorSubmit { .. } => EventKind::FactorResponse { .. } | EventKind::UnlockRejected { .. },
    VaultAuth: Secrets, EventKind::VaultAuthQuery { .. } => EventKind::VaultAuthQueryResponse { .. },
    Lock: Secrets, EventKind::LockRequest { .. } => EventKind::LockResponse { .. },
    LaunchQuery: Launcher, EventKind::LaunchQuery { .. } => EventKind::LaunchQueryResponse { .. },
    LaunchExecute: Launcher, EventKind::LaunchExecute { .. } => EventKind::LaunchExecuteResponse { .. },
    KeyringUnlock: Launcher, EventKind::KeyringUnlockRequest { .. } => EventKind::FactorResponse { .. } | EventKind::UnlockRejected { .. } | EventKind::KeyringUnlockFailed { .. },
    WmListWindows: Wm, EventKind::WmListWindows => EventKind::WmListWindowsResponse { .. },
    WmActivateWindow: Wm, EventKind::WmActivateWindow { .. } => EventKind::WmActivateWindowResponse { .. },
    ClipboardHistory: Clipboard, EventKind::ClipboardHistory { .. } => EventKind::ClipboardHistoryResponse { .. },
    ClipboardClear: Clipboard, EventKind::ClipboardClear { .. } => EventKind::ClipboardClearResponse { .. },
    ClipboardGet: Clipboard, EventKind::ClipboardGet { .. } => EventKind::ClipboardGetResponse { .. },
    InputLayersList: Input, EventKind::InputLayersList => EventKind::InputLayersListResponse { .. },
    InputStatus: Input, EventKind::InputStatus => EventKind::InputStatusResponse { .. },
    InputGrab: Input, EventKind::InputGrabRequest { .. } => EventKind::InputGrabResponse { .. },
    SnippetList: Snippets, EventKind::SnippetList { .. } => EventKind::SnippetListResponse { .. },
    SnippetExpand: Snippets, EventKind::SnippetExpand { .. } => EventKind::SnippetExpandResponse { .. },
    SnippetAdd: Snippets, EventKind::SnippetAdd { .. } => EventKind::SnippetAddResponse { .. },
}
