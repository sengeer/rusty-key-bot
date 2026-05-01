// Объявления модулей
mod config;

// Импорты API из крейтов
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

// runtime tokio через атрибут-макрос
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Инициализация системы логирования
    init_tracing();
    // Использование типа Settings из модуля config
    let settings = config::Settings::from_env()?;

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
