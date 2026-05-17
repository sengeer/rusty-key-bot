// Объявления модулей
mod bot;
mod infra;
mod app;
mod errors;
mod domain;
mod config;

// Импорт хэш-таблицы ключ -> значение
use std::{collections::HashMap, sync::Arc};

// Импорт API из модулей
use app::VaultService;
use bot::BotState;

// Импорты API из крейтов
use teloxide::{dispatching::Dispatcher, dptree, prelude::*};
use tokio::sync::Mutex;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

// runtime tokio через атрибут
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Инициализация системы логирования
    init_tracing();
    // Использование Settings из модуля config
    let settings = config::Settings::from_env()?;

    // Создание пула подключений
    let pool = infra::create_pool(&settings.database_url).await?;
    // Применение миграций к БД
    infra::run_migrations(&pool).await?;

    // Создание репозитория SQLite
    let repo = infra::SqliteVaultRepository::new(pool);
    // Создание реализации CryptoManager
    let crypto = infra::CryptoManager;
    // Сборка VaultService
    let service = Arc::new(VaultService::new(repo, crypto));

    // Создание бота
    let bot = Bot::new(settings.bot_token);
    // Состояние бота
    let state = BotState {
        service,
        pending: Arc::new(Mutex::new(HashMap::new())),
    };

    // Обработчик бота
    let handler = Update::filter_message().endpoint(bot::handle_message);
    // Лог уровня info
    info!("rusty-key bot started");

    // Сборка и запуск диспетчера
    Dispatcher::builder(bot, handler)
        .dependencies(dptree::deps![state])
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;

    Ok(())
}

// Система логирования
fn init_tracing() {
    // Создаёт фильтр
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // Попытка инициализировать логгер, если не получается то выкидывает ошибку
    if let Err(err) = fmt().with_env_filter(filter).try_init() {
        error!("failed to init tracing: {err}");
    }
}
