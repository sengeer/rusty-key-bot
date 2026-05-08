// Объявления модулей
mod infra;
mod app;
mod errors;
mod domain;
mod config;

// Импорты API из крейтов
use tracing::{error};
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
