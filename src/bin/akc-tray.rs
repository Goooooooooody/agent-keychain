#![cfg_attr(windows, windows_subsystem = "windows")]

use agent_keychain::daemon::{
    daemon_status, lock_daemon, run_daemon_locked_with_approval, stop_daemon, unlock_daemon,
    AgentResponse, ApprovalDecision, ApprovalPrompt, ApprovalProvider, APPROVAL_TIMEOUT,
};
use agent_keychain::paths::{config_path, socket_path, vault_path};
use anyhow::{anyhow, Context, Result};
use auto_launch::{
    AutoLaunch, AutoLaunchBuilder, LinuxLaunchMode, MacOSLaunchMode, WindowsEnableMode,
};
use notify_rust::Notification;
use rfd::{MessageButtons, MessageDialog, MessageDialogResult, MessageLevel};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use sysinfo::System;
use tinyfiledialogs::MessageBoxIcon;
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};
use winit::application::ApplicationHandler;
use winit::event::{StartCause, WindowEvent};
use winit::event_loop::{ActiveEventLoop, EventLoop, EventLoopProxy};
use winit::window::WindowId;

const APP_NAME: &str = "Agent Keychain";
enum UserEvent {
    Approval {
        prompt: ApprovalPrompt,
        response: mpsc::SyncSender<ApprovalDecision>,
    },
    Unlock {
        response: mpsc::SyncSender<Option<String>>,
    },
    Menu(MenuEvent),
    Tray(TrayIconEvent),
    Status(Result<AgentResponse, String>),
    DaemonExited(Result<(), String>),
}

struct TrayApprovalProvider {
    proxy: EventLoopProxy<UserEvent>,
}

impl ApprovalProvider for TrayApprovalProvider {
    fn decide(&self, prompt: ApprovalPrompt) -> Result<ApprovalDecision> {
        let (response, receiver) = mpsc::sync_channel(1);
        self.proxy
            .send_event(UserEvent::Approval { prompt, response })
            .map_err(|_| anyhow!("tray event loop is unavailable"))?;
        receiver
            .recv_timeout(APPROVAL_TIMEOUT)
            .map_err(|_| anyhow!("approval timed out"))
    }

    fn unlock(&self) -> Result<Option<String>> {
        let (response, receiver) = mpsc::sync_channel(1);
        self.proxy
            .send_event(UserEvent::Unlock { response })
            .map_err(|_| anyhow!("tray event loop is unavailable"))?;
        receiver
            .recv_timeout(APPROVAL_TIMEOUT)
            .map_err(|_| anyhow!("unlock prompt timed out"))
    }
}

struct TrayMenu {
    status: MenuItem,
    start: MenuItem,
    unlock: MenuItem,
    lock: MenuItem,
    stop: MenuItem,
    launch_at_login: CheckMenuItem,
    quit: MenuItem,
}

impl TrayMenu {
    fn new() -> Result<(Self, Menu)> {
        let menu = Menu::new();
        let status = MenuItem::new("Daemon: starting…", false, None);
        let start = MenuItem::new("Start daemon", false, None);
        let unlock = MenuItem::new("Unlock…", false, None);
        let lock = MenuItem::new("Lock", false, None);
        let stop = MenuItem::new("Stop daemon", false, None);
        let launch_at_login = CheckMenuItem::new(
            "Launch at login",
            true,
            auto_launcher()
                .and_then(|launcher| launcher.is_enabled().map_err(Into::into))
                .unwrap_or(false),
            None,
        );
        let quit = MenuItem::new("Quit Agent Keychain", true, None);
        menu.append_items(&[
            &status,
            &PredefinedMenuItem::separator(),
            &start,
            &unlock,
            &lock,
            &stop,
            &PredefinedMenuItem::separator(),
            &launch_at_login,
            &PredefinedMenuItem::separator(),
            &quit,
        ])?;
        Ok((
            Self {
                status,
                start,
                unlock,
                lock,
                stop,
                launch_at_login,
                quit,
            },
            menu,
        ))
    }

    fn set_stopped(&self) {
        self.status.set_text("Daemon: stopped");
        self.start.set_enabled(true);
        self.unlock.set_enabled(false);
        self.lock.set_enabled(false);
        self.stop.set_enabled(false);
    }

    fn set_starting(&self) {
        self.status.set_text("Daemon: starting…");
        self.start.set_enabled(false);
        self.unlock.set_enabled(false);
        self.lock.set_enabled(false);
        self.stop.set_enabled(true);
    }

    fn set_status(&self, locked: bool, active_grants: usize) {
        self.status.set_text(format!(
            "Daemon: {} • {} grant{}",
            if locked { "locked" } else { "unlocked" },
            active_grants,
            if active_grants == 1 { "" } else { "s" }
        ));
        self.start.set_enabled(false);
        self.unlock.set_enabled(locked);
        self.lock.set_enabled(!locked);
        self.stop.set_enabled(true);
    }

    fn matches(id: &MenuId, item: &impl tray_icon::menu::IsMenuItem) -> bool {
        id == item.id()
    }
}

struct Application {
    proxy: EventLoopProxy<UserEvent>,
    tray_icon: Option<TrayIcon>,
    menu: Option<TrayMenu>,
    daemon_running: bool,
}

impl Application {
    fn start_daemon(&mut self) {
        if self.daemon_running {
            self.refresh_status();
            return;
        }
        self.daemon_running = true;
        if let Some(menu) = &self.menu {
            menu.set_starting();
        }
        let proxy = self.proxy.clone();
        thread::spawn(move || {
            let result = (|| {
                let socket = socket_path()?;
                if daemon_status(socket.clone()).is_ok() {
                    let _ = stop_daemon(socket.clone());
                    for _ in 0..20 {
                        if daemon_status(socket.clone()).is_err() {
                            break;
                        }
                        thread::sleep(Duration::from_millis(50));
                    }
                }
                terminate_existing_daemons();
                run_daemon_locked_with_approval(
                    vault_path()?,
                    socket,
                    config_path()?,
                    Arc::new(TrayApprovalProvider {
                        proxy: proxy.clone(),
                    }),
                )
            })()
            .map_err(|error| format!("{error:#}"));
            let _ = proxy.send_event(UserEvent::DaemonExited(result));
        });
        let proxy = self.proxy.clone();
        thread::spawn(move || {
            let mut status = Err("daemon did not become ready".into());
            for _ in 0..40 {
                thread::sleep(Duration::from_millis(50));
                status = socket_path()
                    .and_then(daemon_status)
                    .map_err(|error| format!("{error:#}"));
                if status.is_ok() {
                    break;
                }
            }
            let _ = proxy.send_event(UserEvent::Status(status));
        });
    }

    fn refresh_status(&self) {
        let proxy = self.proxy.clone();
        thread::spawn(move || {
            let status = socket_path()
                .and_then(daemon_status)
                .map_err(|error| format!("{error:#}"));
            let _ = proxy.send_event(UserEvent::Status(status));
        });
    }

    fn handle_menu(&mut self, event_loop: &ActiveEventLoop, event: MenuEvent) {
        let Some(menu) = &self.menu else {
            return;
        };
        let id = event.id();
        if TrayMenu::matches(id, &menu.start) {
            self.start_daemon();
        } else if TrayMenu::matches(id, &menu.unlock) {
            let proxy = self.proxy.clone();
            thread::spawn(move || {
                if let Some(passphrase) = tinyfiledialogs::password_box(
                    "Unlock Agent Keychain",
                    "Enter the vault passphrase. It is sent only to the local daemon.",
                ) {
                    let status = socket_path()
                        .and_then(|socket| unlock_daemon(socket, passphrase))
                        .and_then(|_| socket_path().and_then(daemon_status))
                        .map_err(|error| format!("{error:#}"));
                    let _ = proxy.send_event(UserEvent::Status(status));
                }
            });
        } else if TrayMenu::matches(id, &menu.lock) {
            let proxy = self.proxy.clone();
            thread::spawn(move || {
                let status = socket_path()
                    .and_then(lock_daemon)
                    .and_then(|_| socket_path().and_then(daemon_status))
                    .map_err(|error| format!("{error:#}"));
                let _ = proxy.send_event(UserEvent::Status(status));
            });
        } else if TrayMenu::matches(id, &menu.stop) {
            if let Ok(socket) = socket_path() {
                let _ = stop_daemon(socket);
            }
        } else if TrayMenu::matches(id, &menu.launch_at_login) {
            match auto_launcher() {
                Ok(launcher) => {
                    let enable = menu.launch_at_login.is_checked();
                    let result = if enable {
                        launcher.enable()
                    } else {
                        launcher.disable()
                    };
                    if let Err(error) = result {
                        menu.launch_at_login.set_checked(!enable);
                        show_error(&format!("Could not update launch-at-login: {error}"));
                    }
                }
                Err(error) => {
                    show_error(&format!("Could not configure launch-at-login: {error:#}"))
                }
            }
        } else if TrayMenu::matches(id, &menu.quit) {
            if let Ok(socket) = socket_path() {
                let _ = stop_daemon(socket);
            }
            event_loop.exit();
        }
    }
}

impl ApplicationHandler<UserEvent> for Application {
    fn new_events(&mut self, _event_loop: &ActiveEventLoop, cause: StartCause) {
        if cause == StartCause::Init {
            match TrayMenu::new().and_then(|(menu, native_menu)| {
                let tray_icon = TrayIconBuilder::new()
                    .with_tooltip(APP_NAME)
                    .with_icon(tray_icon_image()?)
                    .with_icon_as_template(cfg!(target_os = "macos"))
                    .with_menu(Box::new(native_menu))
                    .build()?;
                Ok((menu, tray_icon))
            }) {
                Ok((menu, tray_icon)) => {
                    self.menu = Some(menu);
                    self.tray_icon = Some(tray_icon);
                    self.start_daemon();
                }
                Err(error) => show_error(&format!("Could not start tray application: {error:#}")),
            }
        }
    }

    fn resumed(&mut self, _event_loop: &ActiveEventLoop) {}

    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        _event: WindowEvent,
    ) {
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::Approval { prompt, response } => {
                let proxy = self.proxy.clone();
                thread::spawn(move || {
                    let decision = show_approval(prompt);
                    let _ = response.send(decision);
                    let status = socket_path()
                        .and_then(daemon_status)
                        .map_err(|error| format!("{error:#}"));
                    let _ = proxy.send_event(UserEvent::Status(status));
                });
            }
            UserEvent::Unlock { response } => {
                let proxy = self.proxy.clone();
                thread::spawn(move || {
                    let passphrase = tinyfiledialogs::password_box(
                        "Unlock Agent Keychain",
                        "An agent needs a key. Enter the vault passphrase to continue.",
                    );
                    let _ = response.send(passphrase);
                    let _ = proxy.send_event(UserEvent::Status(
                        socket_path()
                            .and_then(daemon_status)
                            .map_err(|error| format!("{error:#}")),
                    ));
                });
            }
            UserEvent::Menu(event) => self.handle_menu(event_loop, event),
            UserEvent::Tray(_event) => {}
            UserEvent::Status(Ok(AgentResponse::DaemonStatus {
                locked,
                active_grants,
                ..
            })) => {
                self.daemon_running = true;
                if let Some(menu) = &self.menu {
                    menu.set_status(locked, active_grants);
                }
            }
            UserEvent::Status(Ok(_)) => show_error("Daemon returned an unexpected status response"),
            UserEvent::Status(Err(error)) => {
                // Status refreshes race daemon startup, stop, and approval dialogs. Do not
                // turn a transient IPC failure into a generic native application popup; a
                // genuine startup/runtime failure is reported by DaemonExited below.
                let _ = error;
            }
            UserEvent::DaemonExited(result) => {
                self.daemon_running = false;
                if let Some(menu) = &self.menu {
                    menu.set_stopped();
                }
                if let Err(error) = result {
                    show_error(&format!("Daemon stopped unexpectedly: {error}"));
                }
            }
        }
    }
}

fn auto_launcher() -> Result<AutoLaunch> {
    let current_executable = std::env::current_exe().context("resolve tray executable")?;
    let executable_name = current_executable
        .file_name()
        .ok_or_else(|| anyhow!("tray executable has no file name"))?;
    let executable = std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|directory| directory.join(executable_name))
                .find(|candidate| candidate.is_file())
        })
        .unwrap_or(current_executable);
    let executable = executable
        .to_str()
        .ok_or_else(|| anyhow!("tray executable path is not valid UTF-8"))?;
    let mut builder = AutoLaunchBuilder::new();
    builder
        .set_app_name("agent-keychain-tray")
        .set_app_path(executable)
        .set_macos_launch_mode(MacOSLaunchMode::LaunchAgent)
        .set_linux_launch_mode(LinuxLaunchMode::XdgAutostart)
        .set_windows_enable_mode(WindowsEnableMode::CurrentUser);
    builder.build().map_err(Into::into)
}

fn terminate_existing_daemons() {
    let system = System::new_all();
    let mut killed = false;
    for process in system.processes().values() {
        if is_akc_daemon(process.name(), process.cmd()) {
            killed |= process.kill();
        }
    }
    if killed {
        thread::sleep(Duration::from_millis(250));
    }
}

fn is_akc_daemon(name: &std::ffi::OsStr, command: &[std::ffi::OsString]) -> bool {
    matches!(
        name.to_string_lossy().to_ascii_lowercase().as_str(),
        "akc" | "akc.exe"
    ) && command.iter().skip(1).any(|argument| argument == "daemon")
}

fn tray_icon_image() -> Result<Icon> {
    const SIZE: u32 = 32;
    let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
    for y in 3u32..29 {
        for x in 5u32..27 {
            let shield_edge =
                x >= 5 + (y.saturating_sub(20) / 3) && x < 27 - (y.saturating_sub(20) / 3);
            let border = x == 5
                || x == 26
                || y == 3
                || (y >= 20 && (x == 5 + (y - 20) / 3 || x == 26 - (y - 20) / 3));
            let keyhole = (12..=19).contains(&x) && (10..=17).contains(&y)
                || (14..=17).contains(&x) && (17..=23).contains(&y);
            if shield_edge && (border || keyhole) {
                let offset = ((y * SIZE + x) * 4) as usize;
                rgba[offset..offset + 4].copy_from_slice(&[20, 20, 20, 255]);
            }
        }
    }
    Icon::from_rgba(rgba, SIZE, SIZE).map_err(Into::into)
}

fn show_error(message: &str) {
    let message = message.to_owned();
    thread::spawn(move || {
        let _ = Notification::new()
            .summary("Agent Keychain")
            .body(&message)
            .show();
        tinyfiledialogs::message_box_ok("Agent Keychain", &message, MessageBoxIcon::Error);
    });
}

fn show_approval(prompt: ApprovalPrompt) -> ApprovalDecision {
    let secret_label = if prompt.secret_names.len() == 1 {
        format!("Secret: {}", prompt.secret_names[0])
    } else {
        format!("Secrets: {}", prompt.secret_names.join(", "))
    };
    let body = format!(
        "Agent: {}\n{}\nReason: {}\nCommand: {}\nProcess: {}\n\nApprove once, or remember this client for these secret(s)?",
        prompt.agent,
        secret_label,
        prompt.reason.as_deref().unwrap_or("Not provided"),
        prompt.command_context.as_deref().unwrap_or("Not provided"),
        prompt
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "Unavailable".into()),
    );
    let _ = Notification::new()
        .summary("Agent Keychain approval required")
        .body(&format!(
            "{} requests access to {}",
            prompt.agent, secret_label
        ))
        .show();
    let result = MessageDialog::new()
        .set_title("Agent Keychain — approval required")
        .set_description(body)
        .set_level(MessageLevel::Warning)
        .set_buttons(MessageButtons::YesNoCancelCustom(
            "Approve once".into(),
            "Approve automatically".into(),
            "Deny".into(),
        ))
        .show();
    approval_decision_for_dialog(result)
}

fn approval_decision_for_dialog(result: MessageDialogResult) -> ApprovalDecision {
    match result {
        MessageDialogResult::Custom(label) if label == "Approve once" => {
            ApprovalDecision::ApproveOnce
        }
        MessageDialogResult::Custom(label) if label == "Approve automatically" => {
            ApprovalDecision::ApproveAlways
        }
        _ => ApprovalDecision::Deny,
    }
}

fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => {
            println!("akc-tray {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("--help" | "-h") => {
            println!(
                "Agent Keychain desktop approval companion\n\nUsage: akc-tray [--help|--version]"
            );
            return Ok(());
        }
        Some(argument) => return Err(anyhow!("unknown argument: {argument}")),
        None => {}
    }
    let mut builder = EventLoop::<UserEvent>::with_user_event();
    #[cfg(target_os = "macos")]
    {
        use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
        builder.with_activation_policy(ActivationPolicy::Accessory);
    }
    let event_loop = builder.build()?;
    let proxy = event_loop.create_proxy();
    let tray_proxy = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = tray_proxy.send_event(UserEvent::Tray(event));
    }));
    let menu_proxy = proxy.clone();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = menu_proxy.send_event(UserEvent::Menu(event));
    }));
    let mut application = Application {
        proxy,
        tray_icon: None,
        menu: None,
        daemon_running: false,
    };
    event_loop.run_app(&mut application)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{approval_decision_for_dialog, is_akc_daemon};
    use agent_keychain::daemon::ApprovalDecision;
    use rfd::MessageDialogResult;
    use std::ffi::{OsStr, OsString};

    #[test]
    fn takeover_targets_only_akc_daemon_processes() {
        let daemon = [OsString::from("akc"), OsString::from("daemon")];
        let request = [
            OsString::from("akc"),
            OsString::from("agent-get"),
            OsString::from("--name"),
            OsString::from("thing"),
        ];
        assert!(is_akc_daemon(OsStr::new("akc"), &daemon));
        assert!(is_akc_daemon(OsStr::new("akc.exe"), &daemon));
        assert!(!is_akc_daemon(OsStr::new("akc"), &request));
        assert!(!is_akc_daemon(OsStr::new("akc-tray"), &daemon));
    }

    #[test]
    fn approval_dialog_is_default_deny() {
        assert_eq!(
            approval_decision_for_dialog(MessageDialogResult::Cancel),
            ApprovalDecision::Deny
        );
        assert_eq!(
            approval_decision_for_dialog(MessageDialogResult::Custom("Deny".into())),
            ApprovalDecision::Deny
        );
        assert_eq!(
            approval_decision_for_dialog(MessageDialogResult::Custom("Approve once".into())),
            ApprovalDecision::ApproveOnce
        );
    }
}
