// Импорты крейта std
use std:: env;

// Публичная структура Settings
pub struct Settings {
    pub bot_token: String,
    pub database_url: String,
}

// Имплементация Settings
impl Settings {
    // Метод для получения переменных окружения
    pub fn from_env() -> anyhow::Result<Self> {
        // Пытается получить BOT_TOKEN, если не удаётся - замыкание с сообщением
        let bot_token = env::var("BOT_TOKEN")
            .map_err(|_| anyhow::anyhow!("BOT_TOKEN environment variable is required"))?;
        // Пытается получить DATABASE_URL, если не удаётся - замыкание с fallback адресом
        let database_url =
            env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://rusty_key.db".to_string());

        // Возврат результата
        Ok(Self {
            bot_token,
            database_url,
        })
    }
}


