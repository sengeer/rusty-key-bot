CREATE TABLE IF NOT EXISTS users (
    telegram_id INTEGER PRIMARY KEY NOT NULL,
    master_hash TEXT NOT NULL,
    master_salt BLOB NOT NULL,
    key_salt BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    service TEXT NOT NULL,
    login_nonce BLOB NOT NULL,
    login_cipher BLOB NOT NULL,
    password_nonce BLOB NOT NULL,
    password_cipher BLOB NOT NULL,
    note_nonce BLOB,
    note_cipher BLOB,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(telegram_id) ON DELETE CASCADE,
    UNIQUE(user_id, service)
);
