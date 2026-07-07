use crate::cli::prompt_passphrase;
use crate::vault::{Vault, VaultStore};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;
use std::io::{self, Write};
use std::path::PathBuf;

pub fn run_tui(vault_path: PathBuf) -> Result<()> {
    let passphrase = prompt_passphrase()?;
    let store = VaultStore::new(vault_path);
    let mut vault = store.load(&passphrase)?;
    let mut state = ListState::default();
    select_first_if_needed(&vault, &mut state);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = loop {
        terminal.draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Percentage(45),
                    Constraint::Percentage(45),
                    Constraint::Length(2),
                ])
                .split(area);

            let header = Paragraph::new("Agent Keychain — secrets hidden by design")
                .block(Block::default().borders(Borders::ALL).title("akc"));
            frame.render_widget(header, chunks[0]);

            let secret_items: Vec<ListItem> = vault
                .list_names()
                .iter()
                .map(|name| ListItem::new(Line::from(name.clone())))
                .collect();
            let secrets = List::new(secret_items)
                .block(Block::default().borders(Borders::ALL).title("Secrets"))
                .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
                .highlight_symbol("› ");
            frame.render_stateful_widget(secrets, chunks[1], &mut state);

            let audit_items: Vec<ListItem> = vault
                .audit
                .iter()
                .rev()
                .take(12)
                .map(|event| {
                    let name = event.secret_name.clone().unwrap_or_else(|| "-".into());
                    ListItem::new(Line::from(format!(
                        "{} {:?} {} by {}",
                        event.at, event.action, name, event.actor
                    )))
                })
                .collect();
            let audit_widget =
                List::new(audit_items).block(Block::default().borders(Borders::ALL).title("Audit"));
            frame.render_widget(audit_widget, chunks[2]);

            let footer =
                Paragraph::new("↑/↓ select | a add | e edit selected | d delete selected | q quit")
                    .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(footer, chunks[3]);
        })?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                KeyCode::Down => select_next(&vault, &mut state),
                KeyCode::Up => select_previous(&vault, &mut state),
                KeyCode::Char('a') => {
                    suspend_terminal(&mut terminal)?;
                    if let Err(error) = tui_add_secret(&mut vault) {
                        eprintln!("{error:#}");
                        wait_for_enter()?;
                    }
                    store.save(&vault, &passphrase)?;
                    resume_terminal(&mut terminal)?;
                    select_first_if_needed(&vault, &mut state);
                }
                KeyCode::Char('e') => {
                    if let Some(name) = selected_name(&vault, &state) {
                        suspend_terminal(&mut terminal)?;
                        if let Err(error) = tui_edit_secret(&mut vault, &name) {
                            eprintln!("{error:#}");
                            wait_for_enter()?;
                        }
                        store.save(&vault, &passphrase)?;
                        resume_terminal(&mut terminal)?;
                    }
                }
                KeyCode::Char('d') => {
                    if let Some(name) = selected_name(&vault, &state) {
                        suspend_terminal(&mut terminal)?;
                        if confirm(&format!("Delete secret '{name}'?"))? {
                            vault.remove_secret(&name)?;
                            store.save(&vault, &passphrase)?;
                        }
                        resume_terminal(&mut terminal)?;
                        select_first_if_needed(&vault, &mut state);
                    }
                }
                _ => {}
            }
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn selected_name(vault: &Vault, state: &ListState) -> Option<String> {
    let names = vault.list_names();
    state.selected().and_then(|index| names.get(index).cloned())
}

fn select_first_if_needed(vault: &Vault, state: &mut ListState) {
    let names = vault.list_names();
    if names.is_empty() {
        state.select(None);
    } else if state.selected().map_or(true, |index| index >= names.len()) {
        state.select(Some(0));
    }
}

fn select_next(vault: &Vault, state: &mut ListState) {
    let len = vault.list_names().len();
    if len == 0 {
        state.select(None);
        return;
    }
    let next = state.selected().map_or(0, |index| (index + 1) % len);
    state.select(Some(next));
}

fn select_previous(vault: &Vault, state: &mut ListState) {
    let len = vault.list_names().len();
    if len == 0 {
        state.select(None);
        return;
    }
    let previous = state
        .selected()
        .map_or(0, |index| if index == 0 { len - 1 } else { index - 1 });
    state.select(Some(previous));
}

fn tui_add_secret(vault: &mut Vault) -> Result<()> {
    let name = prompt_line("Secret name: ")?;
    let value = rpassword::prompt_password("Secret value: ")?;
    vault.add_secret(name, value)
}

fn tui_edit_secret(vault: &mut Vault, name: &str) -> Result<()> {
    let value = rpassword::prompt_password(format!("New value for '{name}': "))?;
    vault.update_secret(name, value)
}

fn suspend_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn resume_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    enable_raw_mode()?;
    execute!(terminal.backend_mut(), EnterAlternateScreen)?;
    terminal.clear()?;
    Ok(())
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_string())
}

fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt} [y/N]: ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn wait_for_enter() -> Result<()> {
    eprint!("Press Enter to continue...");
    io::stderr().flush()?;
    let mut ignored = String::new();
    io::stdin().read_line(&mut ignored)?;
    Ok(())
}
