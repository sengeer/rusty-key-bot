// Импорты крейта std
use std::{collections::HashMap, sync::Arc};

// Импорт API из внешних крейтов
use teloxide::{prelude::*, types::MessageId};
use tokio::sync::Mutex;

// Групповой импорт модулей
use crate::{
    app::VaultService,
    domain::{PlainEntryInput, generate_password},
    errors::AppError,
    infra::{CryptoManager, SqliteVaultRepository},
};

// Атрибут derive с Clone
#[derive(Clone)]
// Структура BotState
pub struct BotState {
    pub service: Arc<VaultService<SqliteVaultRepository, CryptoManager>>,
    pub pending: Arc<Mutex<HashMap<ChatId, PendingAction>>>,
}

// Атрибут derive с Clone и Debug
#[derive(Clone, Debug)]
// Перечисления PendingAction
pub enum PendingAction {
    SetMaster,
    AddAwaitService,
    AddAwaitLogin {
        service: String,
    },
    AddAwaitPassword {
        service: String,
        login: String,
    },
    AddAwaitNote {
        service: String,
        login: String,
        password: String,
    },
    AddAwaitMaster {
        service: String,
        login: String,
        password: String,
        note: Option<String>,
    },
    GetAwaitMaster {
        service: String,
    },
}

// Обработка сообщения пользователя
pub async fn handle_message(bot: Bot, msg: Message, state: BotState) -> ResponseResult<()> {
    // ID чата
    let chat_id = msg.chat.id;
    // ID пользователя
    let user_id = msg
        .from
        .as_ref()
        .map(|u| u.id.0 as i64)
        .unwrap_or(chat_id.0);
    // Текст сообщения
    let text = msg.text().unwrap_or_default().trim().to_string();

    // Если текст это команда
    if text.starts_with('/') {
        return handle_command(bot, msg, state, user_id, &text).await;
    }

    // Ожидание хода диалога
    let pending = {
        let mut lock = state.pending.lock().await;
        lock.remove(&chat_id)
    };

    // Обработка незаконченного действия
    if let Some(action) = pending {
        return handle_pending(bot, msg, state, user_id, action, &text).await;
    }

    // Если ни одно условие не сработало, отправка сообщения-заглушки
    bot.send_message(
        chat_id,
        "🤷 Не понимаю Ваше сообщение.\n🛟 Используйте /help для списка команд.",
    )
    .await?;
    Ok(())
}

// Обработка всех слэш-команд
async fn handle_command(
    bot: Bot,
    msg: Message,
    state: BotState,
    user_id: i64,
    text: &str,
) -> ResponseResult<()> {
    // ID чата
    let chat_id = msg.chat.id;
    // Части текста разделённые по пробелу
    let mut parts = text.split_whitespace();
    // Первое слово parts, например: /add
    let cmd = parts.next().unwrap_or_default();
    match cmd {
        "/start" => {
            bot.send_message(
                chat_id,
                "🗝️ Rusty Key хранит секреты в зашифрованном виде.\n‼️ Важно: если Telegram-аккаунт скомпрометирован, данные тоже в зоне риска.",
            )
            .await?;
        }
        "/help" => {
            bot.send_message(
                chat_id,
                "/start - начало;\n/help - шпаргалка по командам (мы тут);\n/set_master [master] - установка мастер-пароля;\n/add [service] [login] [password] [note?] - добавить запись указав через пробел: название сервиса, логин, пароль и текст заметки (необязательно). Пример: /add google example@example.com nCOzFyBxXdmDE3rD заметка;\n/get [service] - получить запись по названию сервиса;\n/list - список записей;\n/delete [service] - удалить запись по названию сервиса;\n/gen [len] [special:true|false] - сгенерировать пароль, указав через пробел: длину пароля и использовать ли спец. символы (!@#$%^&*()-_=+[]{};:,.?). Пример: /gen 16 true.",
            )
            .await?;
        }
        "/set_master" => {
            if let Some(master) = parts.next() {

                respond_result(
                    &bot,
                    chat_id,
                    state
                        .service
                        .set_master(user_id, master)
                        .await
                        .map(|_| "🔒 Мастер-пароль установлен/обновлён.".to_string()),
                )
                .await?;
            } else {
                state
                    .pending
                    .lock()
                    .await
                    .insert(chat_id, PendingAction::SetMaster);
                bot.send_message(chat_id, "🔑 Введите новый мастер-пароль следующим сообщением.")
                    .await?;
            }
        }
        "/add" => {
            let args = parts.collect::<Vec<_>>();
            if args.len() >= 3 {
                let service = args[0].to_string();
                let login = args[1].to_string();
                let password = args[2].to_string();
                let note = if args.len() > 3 {
                    Some(args[3..].join(" "))
                } else {
                    None
                };
                ask_master_for_add(&bot, chat_id, &state, service, login, password, note).await?;
            } else {
                state
                    .pending
                    .lock()
                    .await
                    .insert(chat_id, PendingAction::AddAwaitService);
                bot.send_message(chat_id, "1️⃣ Шаг 1/4: отправьте название сервиса.")
                    .await?;
            }
        }
        "/get" => {
            if let Some(service) = parts.next() {
                state.pending.lock().await.insert(
                    chat_id,
                    PendingAction::GetAwaitMaster {
                        service: service.to_string(),
                    },
                );
                bot.send_message(chat_id, "🔐 Введите мастер-пароль для расшифровки записи.")
                    .await?;
            } else {
                bot.send_message(chat_id, "👉 Пример использования: /get google")
                    .await?;
            }
        }
        "/list" => {
            let result = state.service.list_services(user_id).await.map(|services| {
                if services.is_empty() {
                    "👾 Список пуст.".to_string()
                } else {
                    format!("📋 Сервисы:\n- {}", services.join("\n- "))
                }
            });
            respond_result(&bot, chat_id, result).await?;
        }
        "/delete" => {
            if let Some(service) = parts.next() {
                let result = state
                    .service
                    .delete_entry(user_id, service)
                    .await
                    .map(|deleted| {
                        if deleted {
                            "✅ Запись удалена.".to_string()
                        } else {
                            "🤷‍♂️ Запись не найдена.".to_string()
                        }
                    });
                respond_result(&bot, chat_id, result).await?;
            } else {
                bot.send_message(chat_id, "👉 Пример использования: /delete google")
                    .await?;
            }
        }
        "/gen" => {
            let len = parts
                .next()
                .and_then(|x| x.parse::<usize>().ok())
                .unwrap_or(20);
            let with_special = parts
                .next()
                .and_then(|x| x.parse::<bool>().ok())
                .unwrap_or(true);
            let result = generate_password(len, with_special)
                .map(|p| format!("✨ Сгенерированный пароль:\n{p}"));
            respond_result(&bot, chat_id, result).await?;
        }
        _ => {
            bot.send_message(chat_id, "🤷‍♂️ Неизвестная команда. Используйте /help.")
                .await?;
        }
    }
    Ok(())
}

// Обработка ожиданий ответа пользователя
async fn handle_pending(
    bot: Bot,
    msg: Message,
    state: BotState,
    user_id: i64,
    pending: PendingAction,
    text: &str,
) -> ResponseResult<()> {
    let chat_id = msg.chat.id;
    match pending {
        PendingAction::SetMaster => {
            respond_result(
                &bot,
                chat_id,
                state
                    .service
                    .set_master(user_id, text)
                    .await
                    .map(|_| "🔒 Мастер-пароль установлен/обновлён.".to_string()),
            )
            .await?;
            best_effort_delete_message(&bot, chat_id, msg.id).await;
        }
        PendingAction::AddAwaitService => {
            state.pending.lock().await.insert(
                chat_id,
                PendingAction::AddAwaitLogin {
                    service: text.to_string(),
                },
            );
            bot.send_message(chat_id, "2️⃣ Шаг 2/4: отправьте логин.").await?;
        }
        PendingAction::AddAwaitLogin { service } => {
            state.pending.lock().await.insert(
                chat_id,
                PendingAction::AddAwaitPassword {
                    service,
                    login: text.to_string(),
                },
            );
            bot.send_message(chat_id, "3️⃣ Шаг 3/4: отправьте пароль записи.")
                .await?;
        }
        PendingAction::AddAwaitPassword { service, login } => {
            state.pending.lock().await.insert(
                chat_id,
                PendingAction::AddAwaitNote {
                    service,
                    login,
                    password: text.to_string(),
                },
            );
            bot.send_message(chat_id, "4️⃣ Шаг 4/4: отправьте заметку или '-' чтобы пропустить.")
                .await?;
        }
        PendingAction::AddAwaitNote {
            service,
            login,
            password,
        } => {
            let note = if text == "-" {
                None
            } else {
                Some(text.to_string())
            };
            ask_master_for_add(&bot, chat_id, &state, service, login, password, note).await?;
        }
        PendingAction::AddAwaitMaster {
            service,
            login,
            password,
            note,
        } => {
            let input = PlainEntryInput {
                service,
                login,
                password,
                note,
            };
            let result = state
                .service
                .add_entry(user_id, input, text)
                .await
                .map(|_| "✅ Запись сохранена.".to_string());
            respond_result(&bot, chat_id, result).await?;
            best_effort_delete_message(&bot, chat_id, msg.id).await;
        }
        PendingAction::GetAwaitMaster { service } => {
            let result = state
                .service
                .get_entry(user_id, &service, text)
                .await
                .map(|entry| {
                    let note = entry
                        .note
                        .map(|n| format!("\nnote: {n}"))
                        .unwrap_or_default();
                    format!(
                        "service: {}\nlogin: {}\npassword: {}{}",
                        entry.service, entry.login, entry.password, note
                    )
                });
            respond_result(&bot, chat_id, result).await?;
            best_effort_delete_message(&bot, chat_id, msg.id).await;
        }
    }
    Ok(())
}

// Запрос мастер-пароля для добавления записи
async fn ask_master_for_add(
    bot: &Bot,
    chat_id: ChatId,
    state: &BotState,
    service: String,
    login: String,
    password: String,
    note: Option<String>,
) -> ResponseResult<()> {
    state.pending.lock().await.insert(
        chat_id,
        PendingAction::AddAwaitMaster {
            service,
            login,
            password,
            note,
        },
    );
    bot.send_message(chat_id, "🔐 Введите мастер-пароль для сохранения записи.")
        .await?;
    Ok(())
}

// Результирующий ответ
async fn respond_result(
    bot: &Bot,
    chat_id: ChatId,
    result: Result<String, AppError>,
) -> ResponseResult<()> {
    let text = match result {
        Ok(message) => message,
        Err(err) => match err {
            AppError::MasterPasswordNotSet => {
                "🔑 Сначала установите мастер-пароль через /set_master.".to_string()
            }
            AppError::InvalidMasterPassword => "❌ Неверный мастер-пароль.".to_string(),
            AppError::EntryNotFound => "🤷‍♂️ Запись не найдена.".to_string(),
            other => format!("❌ Ошибка: {other}"),
        },
    };
    bot.send_message(chat_id, text).await?;
    Ok(())
}

// Удаление сообщения
async fn best_effort_delete_message(bot: &Bot, chat_id: ChatId, message_id: MessageId) {
    let _ = bot.delete_message(chat_id, message_id).await;
}
